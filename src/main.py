#!/usr/bin/python3
# Shellbang | https://realpython.com/python-shebang/

import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# Files | CONSTANTS
# Those are going to be use outside ?
# no, so, called with '_'
_FILE_INPUT = "control_output.json"
_FILE_OUTPUT = "attestations.json"
_FILE_KEY = "private-key.pem"

# encryption
_ENCRYPT_ALGO = "sha256"
_ENCRYPT_padding = "PKCS1v15"

_ATTESATION_DICKEYS_DATA = "payload"
_ATTESATION_DICKEYS_SIGN = "signature"

# attestation
"""
"type": "static-analysis",
"result": {
    "vulnerabilities": 0,
    "warning": 2,
    "code_smells": 4
},
"user": "developer-1"
"""

# attestation_list json keys
# file output
"""{
"payload" : {},
"signature": ""
"
}
"""


def load_key():
    with open(_FILE_KEY, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    return private_key


# sign
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#signing
def sign_attesation(private_key, _attesation: dict) -> dict:
    _padding = padding.PKCS1v15()

    signature = private_key.sign(_attesation, _padding, hashes.SHA256())

    return signature


# Run as scritp but able to load as module
# https://realpython.com/run-python-scripts/
if __name__ == "__main__":
    # the final list of the attestations write to the file
    attestations = []

    # Context managers are a good try/catch practice
    # we do not need write access to the input, just read
    # The process can be use as script
    with open(_FILE_INPUT, mode="r") as file:
        _data = json.load(file)

    _private_key = load_key()

    for _attesation in _data:
        user_encode_data = json.dumps(_attesation, indent=4).encode("utf-8")
        signature = sign_attesation(_private_key, user_encode_data)

        __aux_attesation = dict()
        __aux_attesation[_ATTESATION_DICKEYS_DATA] = user_encode_data
        __aux_attesation[_ATTESATION_DICKEYS_SIGN] = signature

        attestations.append(__aux_attesation)

    print(attestations)
