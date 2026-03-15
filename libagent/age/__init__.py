"""
Hardware device support for AGE format.

See these links for more details:
 - https://age-encryption.org/v1
 - https://github.com/FiloSottile/age
 - https://github.com/str4d/rage/
"""

import argparse
import base64
import io
import logging
import os
import sys
from importlib import metadata

import bech32
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .. import device, util
from . import client

log = logging.getLogger(__name__)

# X-Wing / ML-KEM-768 constants
XWING_CT_SIZE = 1120
XWING_PK_SIZE = 1216


def bech32_decode(prefix, encoded):
    """Decode Bech32-encoded data."""
    hrp, data = bech32.bech32_decode(encoded)
    assert prefix == hrp
    return bytes(bech32.convertbits(data, 5, 8, pad=False))


def bech32_encode(prefix, data):
    """Encode data using Bech32."""
    return bech32.bech32_encode(prefix, bech32.convertbits(bytes(data), 8, 5))


def run_pubkey(device_type, args):
    """Generate and display age recipient public key."""
    log.warning('This AGE tool is still in EXPERIMENTAL mode, '
                'so please note that the API and features may '
                'change without backwards compatibility!')

    c = client.Client(device=device_type())

    if args.pq:
        run_pubkey_pq(c)
    else:
        run_pubkey_x25519(c, args)


def run_pubkey_x25519(c, args):
    """Generate X25519 (classical) age recipient."""
    pubkey = c.pubkey(identity=client.create_identity(args.identity), ecdh=True)
    recipient = bech32_encode(prefix="age", data=pubkey)
    print(f"# recipient: {recipient}")
    print(f"# SLIP-0017: {args.identity}")
    data = args.identity.encode()
    encoded = bech32_encode(prefix="age-plugin-onlykey-", data=data).upper()
    decoded = bech32_decode(prefix="age-plugin-onlykey-", encoded=encoded)
    assert decoded.startswith(data)
    print(encoded)


def run_pubkey_pq(c):
    """Generate X-Wing (post-quantum) age recipient."""
    from onlykey.age_plugin.cli import encode_recipient, encode_identity
    from onlykey.age_plugin import SLOT_XWING

    print("Generating X-Wing keypair on OnlyKey...", file=sys.stderr)
    pk = c.xwing_keygen()
    assert len(pk) == XWING_PK_SIZE

    recipient = encode_recipient(pk)
    identity = encode_identity(SLOT_XWING)

    print(f"# X-Wing public key (age v1.3.0 mlkem768x25519 compatible)",
          file=sys.stderr)
    print(f"# Recipient: {recipient}", file=sys.stderr)
    print(file=sys.stderr)

    import datetime
    print(f"# created: {datetime.datetime.now().isoformat()}")
    print(f"# recipient: {recipient}")
    print(identity)


def base64_decode(encoded: str) -> bytes:
    """Decode Base64-encoded data (after padding correctly with '=')."""
    k = len(encoded) % 4
    pad = (4 - k) if k else 0
    return base64.b64decode(encoded + ("=" * pad))


# https://github.com/FiloSottile/age/blob/v1.1.0-rc.1/internal/format/format.go#L45
BYTES_PER_LINE = 48


def base64_encode(data: bytes) -> str:
    """Encode data using Base64 (and remove '=')."""
    reader = io.BytesIO(data)
    chunks = map(base64.b64encode, iter(lambda: reader.read(BYTES_PER_LINE), b""))
    chunks = (chunk.replace(b"=", b"") for chunk in chunks)
    return b"\n".join(chunks).decode()


def decrypt(key, encrypted):
    """Decrypt age-encrypted data."""
    cipher = ChaCha20Poly1305(key)
    try:
        return cipher.decrypt(
            nonce=(b"\x00" * 12),
            data=encrypted,
            associated_data=None)
    except InvalidTag:
        return None


def run_decrypt(device_type, args):
    """Unlock hardware device (for future interaction)."""
    # pylint: disable=too-many-locals,too-many-branches
    c = client.Client(device=device_type())

    lines = (line.strip() for line in sys.stdin)  # strip whitespace
    lines = (line for line in lines if line)  # skip empty lines

    identities = []
    x25519_stanzas = {}
    pq_stanzas = {}

    for line in lines:
        log.debug("got %r", line)
        if line == "-> done":
            break

        if line.startswith("-> add-identity "):
            encoded = line.split(" ")[-1].lower()
            data = bech32_decode("age-plugin-onlykey-", encoded)
            identity = client.create_identity(data.decode())
            identities.append(identity)

        elif line.startswith("-> recipient-stanza "):
            parts = line.split(" ")[2:]
            file_index = parts[0]
            tag = parts[1]
            stanza_args = parts[2:]
            body = next(lines)

            if tag == "X25519":
                peer_pubkey = base64_decode(stanza_args[0])
                encrypted = base64_decode(body)
                x25519_stanzas.setdefault(file_index, []).append(
                    (peer_pubkey, encrypted))
            elif tag == "mlkem768x25519":
                enc = base64_decode(stanza_args[0]) if stanza_args else b""
                body_bytes = base64_decode(body)
                pq_stanzas.setdefault(file_index, []).append(
                    (enc, body_bytes))
            else:
                log.debug("skipping unknown stanza type: %s", tag)

    # Handle X25519 (classical) stanzas
    for file_index, stanzas in x25519_stanzas.items():
        _handle_single_file(file_index, stanzas, identities, c)

    # Handle mlkem768x25519 (post-quantum) stanzas
    for file_index, stanzas in pq_stanzas.items():
        _handle_single_file_pq(file_index, stanzas, c)

    send('-> done\n\n')


def _handle_single_file(file_index, stanzas, identities, c):
    """Unwrap file key from X25519 stanzas."""
    d = c.device.__class__.__name__
    for peer_pubkey, encrypted in stanzas:
        for identity in identities:
            id_str = identity.to_string()
            msg = f'Please confirm {id_str} decryption on {d} device...'
            send(f'-> msg\n{base64_encode(msg.encode())}\n')

            key = c.ecdh(identity=identity, peer_pubkey=peer_pubkey)

            result = decrypt(key=key, encrypted=encrypted)
            if not result:
                continue

            send(f'-> file-key {file_index}\n{base64_encode(result)}\n')
            return


def _handle_single_file_pq(file_index, stanzas, c):
    """Unwrap file key from mlkem768x25519 stanzas."""
    try:
        from onlykey.age_plugin.xwing import open_file_key
    except ImportError:
        log.error('Post-quantum decryption requires onlykey[age]: '
                  'pip install onlykey[age]')
        return

    d = c.device.__class__.__name__
    for enc, body in stanzas:
        if len(enc) != XWING_CT_SIZE:
            log.debug("skipping stanza: ciphertext size %d != %d",
                      len(enc), XWING_CT_SIZE)
            continue

        msg = f'Please confirm X-Wing decryption on {d} device...'
        send(f'-> msg\n{base64_encode(msg.encode())}\n')

        try:
            ss = c.xwing_decaps(enc)
            file_key = open_file_key(ss, enc, body)
            send(f'-> file-key {file_index}\n{base64_encode(file_key)}\n')
            return
        except Exception as e:
            log.warning("X-Wing unwrap failed: %s", e)
            continue


def send(msg):
    """Send a response back to `age` binary."""
    sys.stdout.buffer.write(msg.encode())
    sys.stdout.flush()


def main(device_type):
    """Parse command-line arguments."""
    p = argparse.ArgumentParser()

    agent_package = device_type.package_name()
    resources = [metadata.distribution(agent_package), metadata.distribution('lib-agent')]
    versions = '\n'.join('{}={}'.format(r.metadata['Name'], r.version) for r in resources)
    p.add_argument('--version', help='print the version info',
                   action='version', version=versions)

    p.add_argument('-i', '--identity')
    p.add_argument('-v', '--verbose', default=0, action='count')
    p.add_argument('--age-plugin')
    p.add_argument('--pq', action='store_true',
                   help='use post-quantum X-Wing (mlkem768x25519) instead of X25519')

    args = p.parse_args()

    log_path = os.environ.get("ONLYKEY_AGE_PLUGIN_LOG")
    util.setup_logging(verbosity=2, filename=log_path)

    log.debug("starting age plugin: %s", args)

    device_type.ui = device.ui.UI(device_type=device_type, config=vars(args))

    try:
        if args.identity:
            run_pubkey(device_type=device_type, args=args)
        elif args.age_plugin == 'identity-v1':
            run_decrypt(device_type=device_type, args=args)
        else:
            log.error("Unsupported state machine: %r", args.age_plugin)
    except Exception as e:  # pylint: disable=broad-except
        log.exception("age plugin failed: %s", e)

    log.debug("closing age plugin")
