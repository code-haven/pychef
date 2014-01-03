from chef.tests import ChefTestCase, TEST_ROOT
from chef.aes import AES256Cipher
from chef.rsa import SSLError

import base64
import os
import hashlib
import json

class AES256CipherTestCase(ChefTestCase):
    def setUp(self):
        super(AES256CipherTestCase, self).setUp()
        key = hashlib.sha256(open(os.path.join(TEST_ROOT, 'encryption_key')).read()).digest()
        iv = base64.standard_b64decode('GLVikZLxG0SWYnb68Pr8Ag==\n')
        self.cipher = AES256Cipher(key, iv)

    def test_encrypt(self):
        encrypted_value = self.cipher.encrypt('{"json_wrapper":"secr3t c0d3"}')
        self.assertEquals(base64.standard_b64encode(encrypted_value).strip(), "Ym5T8umtSd0wgjDYq1ZDK5dAh6OjgrTxlloGNf2xYhg=")


    def test_decrypt(self):
        decrypted_value = self.cipher.decrypt(base64.standard_b64decode('Ym5T8umtSd0wgjDYq1ZDK5dAh6OjgrTxlloGNf2xYhg=\n'))
        self.assertEquals(decrypted_value, '{"json_wrapper":"secr3t c0d3"}')
