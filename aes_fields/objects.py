"""
objects.py

this module contains the base objects used in en/decrypted,
as well as a compiled regex to test for encryption status
"""

import base64
import re

from . import CIPHER, BLOCK_SIZE, PADDING_CHAR


BASE_64_REGEX = re.compile(r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)')


class AesObject(object):
    """
    the main wrapper for the data being en/decrypted.

    when the data is encrypted, it will then be encoded to base 64 to ensure
    maximum compatibility with various databases' character sets
    """

    def __init__(self, value):
        """
        :param value: non-null data
        """
        try:
            assert value is not None
            self.value = value
        except AssertionError:
            raise ValueError("AesObject value cannot be None")

    @property
    def is_encrypted(self):
        """
        :returns: True if the value is encrypted; else, False
        """
        return re.match(BASE_64_REGEX, self.value) is not None

    def encrypt(self):
        """
        if the value is in a plaintext format, it encrypts it
        """
        if not self.is_encrypted:
            padded = self.value + (BLOCK_SIZE - len(self.value) % BLOCK_SIZE) * PADDING_CHAR
            encrypted = CIPHER.encrypt(padded)
            encoded = base64.b64encode(encrypted)
            self.value = encoded

    def decrypt(self):
        """
        if the value is in a ciphertext format, it decrypts it
        """
        if self.is_encrypted:
            decoded = base64.b64decode(self.value)
            decrypted = CIPHER.decrypt(decoded)
            stripped = decrypted.rstrip(PADDING_CHAR)
            self.value = stripped
