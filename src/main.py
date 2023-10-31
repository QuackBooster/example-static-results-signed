#!/usr/bin/python3
# Shellbang | https://realpython.com/python-shebang/

import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# Files | CONSTANTS
# Those are going to be use outside ?
_FILE_INPUT = "control_output.json"
_FILE_OUTPUT = "attestations.json"
_FILE_KEY = "private-key.pem"

# attestation
_ATTESATION_DICKEYS_DATA = "payload"
_ATTESATION_DICKEYS_SIGN = "signature"


def load_key():
    with open(_FILE_KEY, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    return private_key


# sign
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#signing
def sign_attesation(private_key, _attesation):
    _padding = padding.PKCS1v15()
    signature = private_key.sign(_attesation, _padding, hashes.SHA256())

    return signature


def write_attestation(__attesations: str, __filename=_FILE_OUTPUT) -> None:
    with open(__filename, mode="w") as file:
        file.write((__attesations))


def read_control_inputs(__filename=_FILE_INPUT) -> dict:
    # Context managers are a good try/catch practice
    # we do not need write access to the input, just read
    # The process can be use as script
    with open(__filename, mode="r") as file:
        _data = json.load(file)

    return _data


# Run as scritp but able to load as module
# https://realpython.com/run-python-scripts/
if __name__ == "__main__":
    # the final list of the attestations write to the file
    attestations = []

    _data = read_control_inputs()

    _private_key = load_key()

    for _attesation in _data:
        # user_encode_data just for the sign generation
        control_data = json.dumps(_attesation)

        user_encode_data = control_data.encode("utf-8")

        signature = sign_attesation(_private_key, user_encode_data)

        __aux_attesation = dict()

        # control data pretty formated
        __aux_attesation[_ATTESATION_DICKEYS_DATA] = control_data

        __aux_attesation[_ATTESATION_DICKEYS_SIGN] = str(signature.hex())

        attestations.append(__aux_attesation)

    write_attestation(str(attestations), _FILE_OUTPUT)
