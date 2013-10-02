#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import re


BASE64_REGEX = re.compile(r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)')


class AesObject(object):

    def __init__(self, value):
        self.value = value

    def is_encrypted(self):
        return re.match(BASE64_REGEX, self.value)

    def encrypt(self, cipher, padding, block_size):
        if self.is_encrypted():
            return
        padded = self.value + (block_size - len(self.value) % block_size) * padding
        self.value = base64.b64encode(cipher.encrypt(padded))

    def decrypt(self, cipher, padding):
        if not self.is_encrypted():
            return
        padded = cipher.decrypt(base64.b64decode(self.value))
        self.value = padded.rstrip(padding)
