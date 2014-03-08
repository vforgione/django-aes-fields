"""
fields.py

class used to implement the feature of the application - AES encrypted fields.
this is not comprehensive coverage of all django fields; rather, it covers the main
fields that would need to be covered in cases of PII or other security-related
use cases.

fields covered/wrapped:
    - CharField
    - EmailField
    - TextField
    - IPAddressField

all fields are prefixed with Aes to distinguish from the normal, plaintext fields
"""

from django.db import models

from . import BLOCK_SIZE
from objects import AesObject


class BaseAesField(models.Field):

    __metaclass__ = models.SubfieldBase

    def __init__(self, *args, **kwargs):
        # ensure proper length is given to the value
        kwargs['max_length'] += (BLOCK_SIZE - kwargs['max_length'] % BLOCK_SIZE) % BLOCK_SIZE
        super(BaseAesField, self).__init__(*args, **kwargs)

    def to_python(self, value):
        """
        decrypts the value -- for data coming from the database to the client
        """
        if isinstance(value, AesObject):
            obj = value
        else:
            obj = AesObject(value)
        if obj.is_encrypted:
            obj.decrypt()
        return obj.value

    def get_db_prep_value(self, value, connection, prepared=False):
        """
        encrypts the value -- for data coming from the client to the database
        """
        if isinstance(value, AesObject):
            obj = value
        else:
            obj = AesObject(value)
        if not obj.is_encrypted:
            obj.encrypt()
        return obj.value


class AesCharField(BaseAesField):

    def get_internal_type(self):
        return 'CharField'


class AesEmailField(BaseAesField):

    def get_internal_type(self):
        return 'EmailField'


class AesTextField(BaseAesField):

    def get_internal_type(self):
        return 'TextField'


class AesIPAddressField(BaseAesField):

    def get_internal_type(self):
        return 'IPAddressField'
