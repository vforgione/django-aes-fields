=================
django-aes-fields
=================

django-aes-fields is a set of fields to compliment existing standard django supplied fields. The module offers
the ability to have data that are encrypted in the database and exposed as plaintext in the client side.

Detailed information is available in the "docs" directory.

Quick Start
-----------

1. Add "aes_fields" to your INSTALLED_APPS settings like this:

    INSTALLED_APPS = (
        # django necessary applications
        ...

        # this extension
        "aes_fields",

        # project applications
        ...
    )

2. Build out the necessary configurations in your settings (or preferably local settings) file:

    AES_FIELDS_CONFIG = {
        'KEY': 'some block of text of length 32',   # required -- suggestion is run os.urandom(32) and use that value
        'BLOCK_SIZE': 32,                           # optional -- default 32
        'PADDING': '#',                             # optional -- default #
        'PREFIX': '',                               # optional -- default None
    }
