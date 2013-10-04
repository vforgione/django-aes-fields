#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from setuptools import setup


README = open(os.path.join(os.path.dirname(__file__), 'README.rst')).read()

os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='django-aes-fields',
    version='0.1.1',

    packages=['aes_fields'],
    include_package_data=True,

    install_requires=['pycrypto>=2.6'],

    license='VincePL',

    description='AES field extensions for models.',
    long_description=README,

    author='Vince Forgione',
    author_email='v.forgione@gmail.com',
)
