import io
import pathlib

import pytest

from ... import util
from .. import decode, protocol


def test_subpackets():
    s = io.BytesIO(b'\x00\x05\x02\xAB\xCD\x01\xEF')
    assert decode.parse_subpackets(util.Reader(s)) == [b'\xAB\xCD', b'\xEF']


def test_subpackets_prefix():
    for n in [0, 1, 2, 4, 5, 10, 191, 192, 193,
              255, 256, 257, 8383, 8384, 65530]:
        item = b'?' * n  # create dummy subpacket
        prefixed = protocol.subpackets(item)
        result = decode.parse_subpackets(util.Reader(io.BytesIO(prefixed)))
        assert [item] == result


def test_mpi():
    s = io.BytesIO(b'\x00\x09\x01\x23')
    assert decode.parse_mpi(util.Reader(s)) == 0x123

    s = io.BytesIO(b'\x00\x09\x01\x23\x00\x03\x05')
    assert decode.parse_mpis(util.Reader(s), n=2) == [0x123, 5]


cwd = pathlib.Path(__file__).parent
input_files = cwd.glob('*.gpg')


@pytest.fixture(params=input_files)
def public_key_path(request):
    return request.param


def test_gpg_files(public_key_path):  # pylint: disable=redefined-outer-name
    with open(public_key_path, 'rb') as f:
        assert list(decode.parse_packets(f))


def test_has_custom_subpacket():
    sig = {'unhashed_subpackets': []}
    assert not decode.has_custom_subpacket(sig)

    custom_markers = [
        protocol.CUSTOM_SUBPACKET,
        protocol.subpacket(10, protocol.CUSTOM_KEY_LABEL),
    ]
    for marker in custom_markers:
        sig = {'unhashed_subpackets': [marker]}
        assert decode.has_custom_subpacket(sig)


def test_load_by_keygrip_missing():
    with pytest.raises(KeyError):
        decode.load_by_keygrip(pubkey_bytes=b'', keygrip=b'')


def test_keygrips():
    pubkey_bytes = (cwd / "romanz-pubkey.gpg").open("rb").read()
    keygrips = list(decode.iter_keygrips(pubkey_bytes))
    assert [k.hex() for k in keygrips] == [
        '7b2497258d76bc6539ed88d018cd1c739e2dbb6c',
        '30ae97f3d8e0e34c5ed80e1715fd442ca24c0a8e',
    ]

    for keygrip in keygrips:
        pubkey_dict, user_ids = decode.load_by_keygrip(pubkey_bytes, keygrip)
        assert pubkey_dict['keygrip'] == keygrip
        assert [u['value'] for u in user_ids] == [
            b'Roman Zeyde <roman.zeyde@gmail.com>',
            b'Roman Zeyde <me@romanzey.de>',
        ]
