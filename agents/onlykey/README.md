# onlykey-agent

**Use your [OnlyKey](https://onlykey.io) as a hardware-based SSH and GPG agent.**

`onlykey-agent` lets you perform SSH authentication and GPG operations (signing,
encryption, and decryption) using keys that are generated and stored on an
OnlyKey hardware security device. Your private keys are created on the device
and never leave it — they are never written to disk or exposed to your computer,
which protects them from malware and key-theft even on a compromised host.

It is part of the [`lib-agent`](https://pypi.org/project/lib-agent/) family of
hardware agents (alongside `trezor-agent`, `ledger_agent`, `keepkey_agent`, and
`jade_agent`).

## Features

- **SSH agent** — authenticate to servers and Git hosts with a key held on your OnlyKey.
- **GPG agent** — sign emails, Git commits, and software releases, and decrypt messages.
- **age support** — encrypt and decrypt files with hardware-backed keys.
- **No keys on disk** — keys are generated and stored on the device and never reach the host.

## Installation

```bash
pip install onlykey-agent
```

This installs three console entry points:

- `onlykey-agent` — SSH agent
- `onlykey-gpg` — GPG tool
- `onlykey-gpg-agent` — GPG agent

## Usage

Use your OnlyKey to log in over SSH:

```bash
onlykey-agent user@example.com -c
```

Set up a GPG identity backed by your OnlyKey:

```bash
onlykey-gpg init "Your Name <you@example.com>"
```

Full SSH and GPG instructions, including common use cases, are available in the
[project documentation](https://github.com/trustcrypto/onlykey-agent).

## Requirements

- Python 3.8+
- An [OnlyKey](https://onlykey.io) device
- [`lib-agent`](https://pypi.org/project/lib-agent/) and the
  [`onlykey`](https://pypi.org/project/onlykey/) Python package (installed automatically)

## Links

- Homepage / source: https://github.com/trustcrypto/onlykey-agent
- OnlyKey: https://onlykey.io
- Documentation: https://docs.onlykey.io

## License

Released under the GNU Lesser General Public License v3 (LGPLv3).
