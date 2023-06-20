import json
import os
from enum import Enum
from hashlib import sha256
from pathlib import Path

from Crypto.Cipher import AES
from pysolcrypto.altbn128 import randsn, sbmul, hashs
from pysolcrypto.pedersen import pedersen_com
from pysolcrypto.schnorr import schnorr_create


class DataType(Enum):
    SK = 1
    P = 2
    C = 3
    HS = 4


class ProtocolData:
    def __init__(self, passphrase: str, home_path = Path.home()) -> None:
        self.passphrase = passphrase
        self._secret_path = home_path / ".tsa"
        self._P_path = self._secret_path / "commitment_exponents"
        self._C_path = self._secret_path / "commitments"
        self._HS_path = self._secret_path / "timestamps"
        self._key_path = self._secret_path / "schnorr_key"

        if not os.path.isfile(self._key_path):
            os.mkdir(self._secret_path, mode=0o700)
            # Run Stamp and Extend initialization and keygen
            # Generate secret key and log_g h
            keys = {"a": randsn(), "h": randsn()}
            self.write_data(DataType.SK, keys)
            # Generate a pair of private exponents
            c_1_exps = [{"k": randsn(), "l": randsn()}]
            # Generate first commitment
            c_1 = pedersen_com(
                c_1_exps[0]["k"], c_1_exps[0]["l"], sbmul(keys["h"])
            )
            self.write_data(DataType.P, c_1_exps)
            self.write_data(DataType.C, {1: (c_1[0].n, c_1[1].n)})
            # Create a certificate for A and c_1 in a form of
            # a Schnorr signature
            A = sbmul(keys["a"])
            cert_m = hashs(A[0].n, A[1].n, c_1[0].n, c_1[1].n)
            _, X, S = schnorr_create(keys["a"], cert_m)
            cert = {0: {"X": (X[0].n, X[1].n), "s": S, "l": 0, "i": 0,
                        "data": cert_m}}
            self.write_data(DataType.HS, cert)

    def _derive_data_key(self) -> str:
        """
        Get AES key for the encrypted protocol private data
        from the provided passphrase.
        """
        key = sha256(self.passphrase.encode()).hexdigest()
        return key

    def _encrypt(self, key: str, plaintext: str) -> bytes:
        """Use AES-GCM to encrypt a given plaintext."""
        key_bytes = bytes.fromhex(key)
        data = plaintext.encode()

        cipher = AES.new(key_bytes, AES.MODE_GCM)

        ciphertext, tag = cipher.encrypt_and_digest(data)

        return cipher.nonce + tag + ciphertext

    def _decrypt(self, key: str, ciphertext: bytes) -> str:
        """Use AES-GCM to decrypt a given ciphertext.

        This function raises ValueError if the MAC tag is not valid,
        that is, if the entire message should not be trusted.
        """
        key_bytes = bytes.fromhex(key)

        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=ciphertext[:16])

        plaintext = cipher.decrypt(
            ciphertext=ciphertext[32:]  # , received_mac_tag=ciphertext[16:32]
        )

        return plaintext.decode()

    def _encrypt_on_disk(self, plaintext: str, path: str) -> None:
        """Encrypt given plaintext and store it in a file."""
        key = self._derive_data_key()
        fd = os.open(path=path, flags=os.O_CREAT | os.O_WRONLY, mode=0o700)
        ciphertext = self._encrypt(key=key, plaintext=plaintext)
        os.write(fd, ciphertext)
        os.close(fd)

    def _decrypt_from_disk(self, path: str) -> str:
        """Decrypt data from a given file and return it."""
        key = self._derive_data_key()
        fd = os.open(path=path, flags=os.O_RDONLY)
        ciphertext = os.read(fd, os.path.getsize(path))
        os.close(fd)
        return self._decrypt(key=key, ciphertext=ciphertext)

    def get_data(self, type: DataType):
        """Read requested file and parse it from JSON."""
        if type == DataType.SK:
            raw_data = self._decrypt_from_disk(self._key_path)
        elif type == DataType.P:
            raw_data = self._decrypt_from_disk(self._P_path)
        elif type == DataType.C:
            raw_data = self._decrypt_from_disk(self._C_path)
        elif type == DataType.HS:
            raw_data = self._decrypt_from_disk(self._HS_path)
        else:
            raise ValueError("No such DataType.")
        return json.loads(raw_data)

    def write_data(self, type: DataType, data):
        """Write to requested file in JSON format."""
        raw_data = json.dumps(data)
        if type == DataType.SK:
            self._encrypt_on_disk(raw_data, self._key_path)
        elif type == DataType.P:
            self._encrypt_on_disk(raw_data, self._P_path)
        elif type == DataType.C:
            self._encrypt_on_disk(raw_data, self._C_path)
        elif type == DataType.HS:
            self._encrypt_on_disk(raw_data, self._HS_path)
        else:
            raise ValueError("No such DataType.")
