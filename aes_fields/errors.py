#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging


class MissingConfigurationError(Exception):

    def __init__(self):
        super(MissingConfigurationError, self).__init__("missing `AES_FIELDS_CONFIGURATION` in your settings")


class MissingRequiredSettingError(Exception):

    def __init__(self, key):
        super(MissingRequiredSettingError, self).__init__("missing `{}` from AES_FIELDS_CONFIGURATION".format(key))


def default_value_warning(key, value):
    logging.debug("{} missing from AES_FIELDS_CONFIGURATION - using default value `{}`".format(key, value))
