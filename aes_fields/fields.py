#!/usr/bin/env python
# -*- coding: utf-8 -*-

from Crypto.Cipher import AES
from django.conf import settings
from django.db import models

from . import AesObject
from .errors import MissingConfigurationError, MissingRequiredSettingError, default_value_warning

try:
    from south.modelsinspector import add_introspection_rules
except ImportError:
    add_introspection_rules = lambda x, y: x or y  # redefine to not do anything

# get configuration from settings
try:
    CONFIG = settings.AES_FIELDS_CONFIGURATION
except KeyError:
    raise MissingConfigurationError()

try:
    KEY = CONFIG['KEY']
except KeyError:
    raise MissingRequiredSettingError('KEY')

try:
    PADDING = CONFIG['PADDING']
    if len(PADDING) != 1:
        raise ValueError("`PADDING` must have len() = 1 (single character)")
except KeyError:
    PADDING = '#'
    default_value_warning('PADDING', '#')

try:
    BLOCK_SIZE = CONFIG['BLOCK_SIZE']
    # let the AES module handle exceptions for block size
except KeyError:
    BLOCK_SIZE = 32
    default_value_warning('BLOCK_SIZE', 32)

try:
    PREFIX = CONFIG['PREFIX']
    if PREFIX is not None and not str(PREFIX).endswith(':'):
        PREFIX = str(PREFIX) + ':'
except KeyError:
    PREFIX = None
    default_value_warning('PREFIX', None)


# create cipher object
CIPHER = AES.new(KEY)


# define fields
class BaseAesField(models.Field):

    __metaclass__ = models.SubfieldBase

    def __init__(self, *args, **kwargs):
        kwargs['max_length'] += (BLOCK_SIZE - (kwargs['max_length'] % BLOCK_SIZE)) % BLOCK_SIZE
        super(BaseAesField, self).__init__(*args, **kwargs)

    def to_python(self, value):
        """decrypts the value

        :param value: an encrypted value
        """
        if isinstance(value, AesObject):
            obj = value
        else:
            if PREFIX and str(value).startswith(PREFIX):
                value = value[len(PREFIX):]
            obj = AesObject(value)
        if obj.is_encrypted():
            obj.decrypt(CIPHER, PADDING)
        return obj.value

    def get_db_prep_value(self, value, connection, prepared=False):
        """encrypts (and optionally prefixes) the value

        :param value: a plaintext value
        :param connection: the database connection
        :param prepared: flags if the value has been prepared
        """
        if isinstance(value, AesObject):
            obj = value
        else:
            obj = AesObject(value)
        if not obj.is_encrypted():
            obj.encrypt(CIPHER, BLOCK_SIZE, PADDING)
        if PREFIX and not str(obj.value).startswith(PREFIX):
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


add_introspection_rules([], '^aes_fields\.fields\.AesEmailField')
add_introspection_rules([], '^aes_fields\.fields\.AesCharField')
add_introspection_rules([], '^aes_fields\.fields\.AesTextField')
add_introspection_rules([], '^aes_fields\.fields\.AesIPAddressField')
add_introspection_rules([], '^aes_fields\.fields\.AesGenericIPAddressField')
