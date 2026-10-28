"""Cifrado por sobre (envelope encryption).

Cada secreto se cifra con su propia clave de datos (DEK, AES-256-GCM). La DEK se guarda
cifrada con la clave maestra (KEK). El AAD liga el texto cifrado al id de la credencial,
de modo que no se puede copiar un blob a otra fila sin que falle la autenticación.
"""

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE_LEN = 12


class Cipher:
    def __init__(self, kek: bytes):
        if len(kek) != 32:
            raise ValueError("La KEK debe tener 32 bytes")
        self._kek = AESGCM(kek)
        self._kek_raw = kek

    def encrypt(self, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
        """Devuelve (dek_envuelta, blob)."""
        dek = AESGCM.generate_key(bit_length=256)
        n1 = os.urandom(NONCE_LEN)
        wrapped = n1 + self._kek.encrypt(n1, dek, b"dek:" + aad)
        n2 = os.urandom(NONCE_LEN)
        blob = n2 + AESGCM(dek).encrypt(n2, plaintext, aad)
        return wrapped, blob

    def decrypt(self, wrapped_dek: bytes, blob: bytes, aad: bytes) -> bytes:
        dek = self._kek.decrypt(wrapped_dek[:NONCE_LEN], wrapped_dek[NONCE_LEN:], b"dek:" + aad)
        return AESGCM(dek).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], aad)

    def derive_subkey(self, label: bytes) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"llaverito:" + label).derive(
            self._kek_raw
        )
