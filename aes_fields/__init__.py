"""
__init__.py

pulls in settings declared in settings.py and creates a cipher object
"""

from django.core.exceptions import ImproperlyConfigured
from django.conf import settings


# the key used for creating the aes cipher object
try:
    KEY = str(settings.AES_KEY)
    assert len(KEY) == 32
except ImproperlyConfigured:
    raise ImproperlyConfigured("AES_KEY is required to be in your settings")
except AssertionError:
    raise ImproperlyConfigured("AES_KEY must be a string of length 32")


# the character used to pad out plaintext to meet block size
try:
    PADDING_CHAR = str(settings.AES_PADDING_CHAR)
    assert len(PADDING_CHAR) == 1
except ImproperlyConfigured:
    PADDING_CHAR = ' '  # white space gets stripped anyway, so why not?
except AssertionError:
    raise ImproperlyConfigured("AES_PADDING_CHAR must be string of length 1")


# the block sized used for encryption
try:
    BLOCK_SIZE = int(settings.AES_BLOCK_SIZE)
    assert BLOCK_SIZE in (16, 24, 32)
except ImproperlyConfigured:
    BLOCK_SIZE = 32
except ValueError:
    raise ImproperlyConfigured("AES_BLOCK_SIZE must be an integer")
except AssertionError:
    raise ImproperlyConfigured("AES_BLOCK_SIZE must be equal to 16, 24 or 32")


# build cipher object
from Crypto.Cipher import AES

CIPHER = AES.new(KEY)
