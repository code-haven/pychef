from chef.exceptions import ChefUnsupportedEncryptionVersionError, ChefDecryptionError
from chef.aes import AES256Cipher, EVP_MAX_IV_LENGTH
from chef.utils import json
from chef.data_bag import DataBagItem

import os
import sys
import hmac
import base64
import chef
import hashlib
import binascii
import itertools
import six
from six.moves import filterfalse, zip_longest


class EncryptedDataBagItem(DataBagItem):
    """An Encrypted Chef data bag item object.

    Encrypted Databag Items behave in the same way as :class:`DatabagItem`
    except the keys and values are encrypted as detailed in the Chef docs:
    https://docs.chef.io/data_bags.html#encrypt-a-data-bag-item

    Refer to the :class:`DatabagItem` documentation for usage.
    """
    SUPPORTED_ENCRYPTION_VERSIONS = (1,2)
    AES_MODE = 'aes_256_cbc'

    def __getitem__(self, key):
        if key == 'id':
            return self.raw_data[key]
        else:
            return create_decryptor(self.api.encryption_key, self.raw_data[key]).decrypt()

    def __setitem__(self, key, value):
        if key == 'id':
            self.raw_data[key] = value
        else:
            self.raw_data[key] = create_encryptor(self.api.encryption_key, value, self.api.encryption_version).to_dict()

def create_encryptor(key, data, version):
    try:
        return {
            1: EncryptorVersion1(key, data),
            2: EncryptorVersion2(key, data)
            }[version]
    except KeyError:
        raise ChefUnsupportedEncryptionVersionError(version)

class EncryptorVersion1(object):
    VERSION = 1

    def __init__(self, key, data):
        self.plain_key = key.encode('utf8')
        self.key = hashlib.sha256(key.encode('utf8')).digest()
        self.data = data
        self.iv = binascii.hexlify(os.urandom(int(EVP_MAX_IV_LENGTH/2)))
        self.encryptor = AES256Cipher(key=self.key, iv=self.iv)
        self.encrypted_data = None

    def encrypt(self):
        if self.encrypted_data is None:
            data = json.dumps({'json_wrapper': self.data})
            self.encrypted_data = self.encryptor.encrypt(data)
        return self.encrypted_data

    def to_dict(self):
        return {
            "encrypted_data": base64.standard_b64encode(self.encrypt()).decode('utf8'),
            "iv": base64.standard_b64encode(self.iv).decode('utf8'),
            "version": self.VERSION,
            "cipher": "aes-256-cbc"
            }

class EncryptorVersion2(EncryptorVersion1):
    VERSION = 2

    def __init__(self, key, data):
        super(EncryptorVersion2, self).__init__(key, data)
        self.hmac = None

    def encrypt(self):
        self.encrypted_data = super(EncryptorVersion2, self).encrypt()
        self.hmac = (self.hmac if self.hmac is not None else self._generate_hmac())
        return self.encrypted_data

    def _generate_hmac(self):
        raw_hmac = hmac.new(self.plain_key, base64.standard_b64encode(self.encrypted_data), hashlib.sha256).digest()
        return raw_hmac

    def to_dict(self):
        result = super(EncryptorVersion2, self).to_dict()
        result['hmac'] = base64.standard_b64encode(self.hmac).decode('utf8')
        return result

def get_decryption_version(data):
    if 'version' in data:
        if str(data['version']) in map(str, EncryptedDataBagItem.SUPPORTED_ENCRYPTION_VERSIONS):
            return data['version']
        else:
            raise ChefUnsupportedEncryptionVersionError(data['version'])
    else:
        return 1

def create_decryptor(key, data):
    version = get_decryption_version(data)
    if version == 1:
        return DecryptorVersion1(key, data['encrypted_data'], data['iv'])
    elif version == 2:
        return DecryptorVersion2(key, data['encrypted_data'], data['iv'], data['hmac'])

class DecryptorVersion1(object):
    def __init__(self, key, data, iv):
        self.key = hashlib.sha256(key.encode('utf8')).digest()
        self.data = base64.standard_b64decode(data)
        self.iv = base64.standard_b64decode(iv)
        self.decryptor = AES256Cipher(key=self.key, iv=self.iv)

    def decrypt(self):
        value = self.decryptor.decrypt(self.data)
        # After decryption we should get a string with JSON
        try:
            value = json.loads(value.decode('utf-8'))
        except ValueError:
            raise ChefDecryptionError("Error decrypting data bag value. Most likely the provided key is incorrect")
        return value['json_wrapper']

class DecryptorVersion2(DecryptorVersion1):
    def __init__(self, key, data, iv, hmac):
        super(DecryptorVersion2, self).__init__(key, data, iv)
        self.hmac = base64.standard_b64decode(hmac)
        self.encoded_data = data

    def _validate_hmac(self):
        encoded_data = self.encoded_data.encode('utf8')

        expected_hmac = hmac.new(self.key, encoded_data, hashlib.sha256).digest()
        valid = len(expected_hmac) ^ len(self.hmac)
        for expected_char, candidate_char in zip_longest(expected_hmac, self.hmac):
            if sys.version_info[0] > 2:
                valid |= expected_char ^ candidate_char
            else:
                valid |= ord(expected_char) ^ ord(candidate_char)
            
        return valid == 0

    def decrypt(self):
        if self._validate_hmac():
            return super(DecryptorVersion2, self).decrypt()
        else:
            raise ChefDecryptionError("Error decrypting data bag value. HMAC validation failed.")

