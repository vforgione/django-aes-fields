#!/usr/bin/env python
# -*- coding: utf-8 -*-

from Crypto.Cipher import AES
from django.conf import settings
from django.db import models

from aes_fields.exceptions import MissingConfigurationError, ConfigurationError
from aes_fields.base_objects import AesObject


# get configuration from settings
try:
    CONFIG = settings.AES_FIELDS_CONFIGURATION
except KeyError:
    raise MissingConfigurationError()

try:
    KEY = CONFIG['KEY']
except KeyError:
    raise ConfigurationError("`KEY` missing from configuration")

PADDING = CONFIG.get('PADDING', '#')
if len(PADDING) != 1:
    raise ConfigurationError("`PADDING` must have len() == 1: yours is {}".format(len(PADDING)))

BLOCK_SIZE = int(CONFIG.get('BLOCK_SIZE', 32))
if BLOCK_SIZE % 8 != 0:
    raise ConfigurationError("`BLOCK_SIZE` must be %8 == 0 for encryption. yours is {}".format(BLOCK_SIZE % 8))

PREFIX = CONFIG.get('PREFIX', None)
if PREFIX and not PREFIX.endswith(':'):
    PREFIX += ':'


class BaseAesField(models.Field):

    __metaclass__ = models.SubfieldBase

    def __init__(self, *args, **kwargs):
        self.cipher = AES.new(KEY)
        kwargs['max_length'] += (BLOCK_SIZE - (kwargs['max_length'] % BLOCK_SIZE)) % BLOCK_SIZE
        super(BaseAesField, self).__init__(*args, **kwargs)

    def to_python(self, value):
        if isinstance(value, AesObject):
            obj = value
        else:
            if PREFIX and value.startswith(PREFIX):
                value = value[len(PREFIX):]
            obj = AesObject(value)
        if not obj.is_encrypted():
            return value
        obj.decrypt(self.cipher, PADDING)
        return obj.value

    def get_db_prep_value(self, value, connection, prepared=False):
        if isinstance(value, AesObject):
            obj = value
        else:
            obj = AesObject(value)
        if obj.is_encrypted():
            return obj.value
        obj.encrypt(self.cipher, PADDING, BLOCK_SIZE)
        if PREFIX:
            return PREFIX + obj.value
        return obj.value


class AesEmailField(BaseAesField):

    def get_internal_type(self):
        return 'EmailField'


class AesCharField(BaseAesField):

    def get_internal_type(self):
        return 'CharField'


class AesTextField(BaseAesField):

    def get_internal_type(self):
        return 'TextField'


class AesIPAddressField(BaseAesField):

    def get_internal_type(self):
        return 'IPAddressField'


class AesGenericIPAddressField(BaseAesField):

    def get_internal_type(self):
        return 'GenericIPAddressField'
