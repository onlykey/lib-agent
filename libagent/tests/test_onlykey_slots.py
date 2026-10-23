import sys

from ..device import onlykey


def _slots(tmpdir, monkeypatch, platform, launcher, text):
    """The slots get_sk_dk() reads back from the launcher `onlykey-gpg init` wrote."""
    tmpdir.join(launcher).write(text)
    monkeypatch.setattr(sys, 'platform', platform)
    monkeypatch.setenv('AGENTHOMEDIR', str(tmpdir))
    dev = onlykey.OnlyKey.__new__(onlykey.OnlyKey)  # no device needed
    dev.get_sk_dk()
    return dev.skeyslot, dev.dkeyslot


def test_slots_from_run_agent_sh(tmpdir, monkeypatch):
    text = '#!/bin/sh\nexport PATH="/usr/bin"\nonlykey-gpg-agent \\\n-vv \\\n' \
           '--skey-slot=ECC1 \\\n--dkey-slot=ECC2 \\\n$*\n'
    assert _slots(tmpdir, monkeypatch, 'linux', 'run-agent.sh', text) == (101, 102)


def test_slots_from_run_agent_cmd(tmpdir, monkeypatch):
    text = ('@echo off\nset "PATH=C:\\Windows"\n"C:\\py\\pythonw.exe" '
            '"C:\\py\\Scripts\\onlykey-gpg-agent.exe" -vv --skey-slot=ECC1 --dkey-slot=ECC2 %*\n')
    assert _slots(tmpdir, monkeypatch, 'win32', 'run-agent.cmd', text) == (101, 102)
