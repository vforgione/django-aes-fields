#!/usr/bin/env python
# -*- coding: utf-8 -*-


class MissingConfigurationError(Exception):

    def __init__(self):
        """
        an error for a completely missing configuration directory
        """
        super(MissingConfigurationError, self).__init__("no `AES_FIELDS_CONFIGURATION` found in settings.")


class ConfigurationError(Exception):

    def __init__(self, error):
        """
        an error for missing necessary configuration key

        :param key: the missing key
        """
        super(ConfigurationError, self).__init__(error)
