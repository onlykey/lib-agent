"""OnlyKey-related definitions."""

# pylint: disable=unused-import,import-error,no-name-in-module

from onlykey import Message, OnlyKey
# Shared protocol logic (generated from libraries/onlykey/protocol/onlykey-protocol.json):
# the 3-digit challenge rule and the "is this reply an Error string?" classifier live
# there, not here.
from onlykey.protocol import (AGENT_DERIVATION, CapabilityFlag, KeyType,
                              challenge_code, classify_response)
