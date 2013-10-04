#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import re


BASE64_REGEX = re.compile(r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)')


class AesObject(object):

    def __init__(self, value):
        """initializes the object

        :param value: a non-null datum
        """
        if value is not None:
            self.value = unicode(value)
        else:
            raise TypeError("AesObject value cannot be None")

    def is_encrypted(self):
        """determine if the object's value is encrypted

        :returns: True if the value is encrypted; else False
        """
        return re.match(BASE64_REGEX, self.value) is not None

    def encrypt(self, cipher, block_size, padding):
        """encrypts the value of the object

        :param cipher: an AES cipher object
        :param block_size: an integer dictating the block size to be used in the encryption rounds
        :param padding: a character to be used to pad the object's value
        """
        if self.is_encrypted():
            return
        padded = self.value + (block_size - len(self.value) % block_size) * unicode(padding)
        encrypted = cipher.encrypt(padded)
        encoded = base64.b64encode(encrypted)
        self.value = encoded

    def decrypt(self, cipher, padding):
        """decrypts the object's value

        :param cipher: an AES cipher object
        :param padding: the character used to pad the plaintext value for encryption that needs to now be stripped
        """
        if not self.is_encrypted():
            return
        decoded = base64.b64decode(self.value)
        decrypted = cipher.decrypt(decoded)
        stripped = decrypted.rstrip(padding)
        self.value = stripped
