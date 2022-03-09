"""Device abstraction layer for GPG operations."""

import logging

from .. import formats, util
from ..device import interface

log = logging.getLogger(__name__)


def create_identity(user_id, curve_name):
    """Create GPG identity for hardware device."""
    result = interface.Identity(identity_str='gpg://', curve_name=curve_name)
    result.identity_dict['host'] = user_id
    return result


class Client:
    """Sign messages and get public keys from a hardware device."""

    def __init__(self, device):
        """C-tor."""
        self.device = device

    def pubkey(self, identity, ecdh=False):
        """Return public key as VerifyingKey object."""
        with self.device:
            if self.device.package_name() == 'onlykey-agent':
                pubkey = self.device.pubkey(ecdh=ecdh, identity=identity)
                public_key = pubkey
            else:
                pubkey = self.device.pubkey(ecdh=ecdh, identity=identity)
                public_key = formats.decompress_pubkey(pubkey=pubkey,
                                                       curve_name=identity.curve_name)
        return public_key

    def sign(self, identity, digest):
        """Sign the digest and return a serialized signature."""
        log.info('please confirm GPG signature on %s for "%s"...',
                 self.device, identity.to_string())
        if identity.curve_name == formats.CURVE_NIST256:
            digest = digest[:32]  # sign the first 256 bits
        log.debug('signing digest: %s', util.hexlify(digest))
        log.debug('identity type: %s', identity.curve_name)
        if (identity.curve_name == 'rsa2048' or identity.curve_name == 'rsa4096') and len(digest) == 32: 
            self.device.sig_hash(b'rsa-sha2-256')
        elif (identity.curve_name == 'rsa2048' or identity.curve_name == 'rsa4096') and len(digest) == 64: 
            self.device.sig_hash(b'rsa-sha2-512')
        with self.device:
            sig = self.device.sign(blob=digest, identity=identity)
        if (identity.curve_name == 'rsa2048' or identity.curve_name == 'rsa4096'):
            return util.bytes2num(sig)
        else:
            return (util.bytes2num(sig[:32]), util.bytes2num(sig[32:]))

    def ecdh(self, identity, pubkey):
        """Derive shared secret using ECDH from remote public key."""
        log.info('please confirm GPG decryption on %s for "%s"...',
                 self.device, identity.to_string())
        with self.device:
            return self.device.ecdh(pubkey=pubkey, identity=identity)
