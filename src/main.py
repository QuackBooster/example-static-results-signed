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
"""{
"payload" : {},
"signature": ""
"
}
"""

# file output
# []


def load_key():
    with open(_FILE_KEY, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    print(private_key)


def encrypt_attesation(key: str, _attesation: dict) -> dict:
    print("Hello from def")
    print(_attesation["user"])
    print()
    message = b"A message I want to sign"
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


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
        print(type(file))
        # _json_str = json.dumps(_data, indent=4)

    # print(_json_str)
    # print(_data)

    load_key()

    for _attesation in _data:
        # print(_attesation)
        # encrypt_attesation(_attesation)
        print("x")
