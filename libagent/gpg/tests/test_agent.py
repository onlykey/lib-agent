import mock
import pytest

from ... import util
from .. import agent


def test_sig_encode():
    SIG = (
        b'(7:sig-val(5:ecdsa(1:r32:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x0c)(1:s32:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00")))')
    assert agent.sig_encode(12, 34) == SIG


# A real GnuPG 2.4 encryption to a cv25519 subkey (AES-256 session key, AES-128 key
# wrap, SHA-256 KDF); gpg --show-session-key gave 9:6A7D1A6B...F6AD287E. The X25519
# shared secret was computed from the exported secret subkey.
KEM_E = bytes.fromhex('40b18a5df1abbad63d5fce3f0e71a9ba85657e066d94c711593530e4c11e2a5d04')
KEM_S = bytes.fromhex('30bd9e5a20b8d78ec028817ff1dc3bab57a83a144c0f142f219a09b75106c8c9'
                      '32d97491a348b566d45379870fc619ff2d')
KEM_KDF_PARAMS = bytes.fromhex('0a2b0601040197550105011203010807416e6f6e796d6f75732053656e646572'
                               '20202020f0e0d7e6ccb7330cb0a9714d3082cec72555966f')
KEM_SHARED = bytes.fromhex('1cfac96271fe26459c31ab98e865b5fde241ace9f858b0254c1f983a5750d018')
KEM_SESSION_KEY = bytes.fromhex('096a7d1a6bfb6429ef0dc70d1ad32721503373b0ea0550bdf49d6d9512f6ad287e'
                                '0e890505050505')


def _kem_params(override=None):
    params = {b'c': b'7', b'h': b'8', b'e': KEM_E, b's': KEM_S, b'kdf-params': KEM_KDF_PARAMS}
    params.update(override or {})
    return params


def test_kem_pgp_session_key_matches_gnupg():
    # The device returns the X25519 result with a 0x04 prefix byte.
    assert agent.kem_pgp_session_key(_kem_params(), b'\x04' + KEM_SHARED) == KEM_SESSION_KEY
    assert agent.kem_pgp_session_key(_kem_params(), KEM_SHARED) == KEM_SESSION_KEY


def test_kem_pgp_session_key_refuses_what_it_cannot_unwrap():
    with pytest.raises(agent.AgentError):
        agent.kem_pgp_session_key(_kem_params(), b'\x04' + bytes(32))  # wrong shared secret
    with pytest.raises(agent.AgentError):
        agent.kem_pgp_session_key(_kem_params({b't': b'9580'}), KEM_SHARED)  # RFC 9580 key
    with pytest.raises(agent.AgentError):
        agent.kem_pgp_session_key(_kem_params({b's': KEM_S[:-1]}), KEM_SHARED)  # bad length


def test_pkdecrypt_kem_pgp_returns_the_session_key():
    """GnuPG 2.5 sends PKDECRYPT --kem=PGP with an (enc-val (ecc ...)) ciphertext."""
    sexp = (b'(7:enc-val(3:ecc(1:c1:7)(1:h1:8)(1:e33:' + KEM_E + b')(1:s49:' + KEM_S + b')'
            b'(10:kdf-params' + str(len(KEM_KDF_PARAMS)).encode() + b':' + KEM_KDF_PARAMS + b')))')
    lines = iter([b'D ' + util.assuan_serialize(sexp), b'END'])
    sent = []
    handler = agent.Handler.__new__(agent.Handler)
    handler.keygrip = b'00' * 20
    handler.get_identity = lambda keygrip: mock.Mock(curve_name='curve25519')
    handler.client = mock.Mock()
    handler.client.ecdh.return_value = b'\x04' + KEM_SHARED
    with mock.patch.object(agent.keyring, 'recvline', lambda conn: next(lines)), \
            mock.patch.object(agent.keyring, 'sendline', lambda conn, msg: sent.append(msg)):
        handler.pkdecrypt(None, (b'--kem=PGP',))
    handler.client.ecdh.assert_called_once_with(identity=mock.ANY, pubkey=KEM_E)
    assert b'S PADDING 0' not in sent
    assert sent[-1] == b'D ' + util.assuan_serialize(b'(5:value40:' + KEM_SESSION_KEY + b')')


def test_pkdecrypt_refuses_the_composite_kem():
    handler = agent.Handler.__new__(agent.Handler)
    with pytest.raises(agent.AgentError):
        handler.pkdecrypt(None, (b'--kem=PQC-PGP',))
