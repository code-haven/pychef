from chef import DataBag, EncryptedDataBagItem
from chef.exceptions import ChefError, ChefUnsupportedEncryptionVersionError, ChefDecryptionError
from chef.tests import ChefTestCase, TEST_ROOT
from chef.api import ChefAPI
from chef.encrypted_data_bag_item import get_decryption_version

import copy
import os

class EncryptedDataBagItemTestCase(ChefTestCase):
    def setUp(self):
        super(EncryptedDataBagItemTestCase, self).setUp()

        """
        This is data encoded using knife, it contains two examples of
        encryption methods versions: 1 and 2.
        """
        self.knife_examples = {
            'id': 'test',
            "pychef_test_ver1": {
                "encrypted_data": "Ym5T8umtSd0wgjDYq1ZDK5dAh6OjgrTxlloGNf2xYhg=\n",
                "iv": "GLVikZLxG0SWYnb68Pr8Ag==\n",
                "version": 1,
                "cipher": "aes-256-cbc"
                },
            "pychef_test_ver2": {
                "encrypted_data": "m2UCN7TYqRJhGfeGFCWtdlF8qtz15W8EmCRqQ4TI4nJpGm/Bqe1WgnzekJus\n7aM0\n",
                "hmac": "mzhfGpf/7rkkIQOSbK22zUv1X+bTCNI2l3FgMBgVOAY=\n",
                "iv": "EKNLqsxNfiFFDZPDnyXRfw==\n",
                "version": 2,
                "cipher": "aes-256-cbc"
                }
            }

    def test__getitem__(self):
        api = ChefAPI('https://chef_test:3000', os.path.join(TEST_ROOT, 'client.pem'), 'admin', secret_file=os.path.join(TEST_ROOT, 'encryption_key'))
        bag = DataBag('test_1')
        item = EncryptedDataBagItem(bag, 'test', api, True)
        item.raw_data = copy.deepcopy(self.knife_examples)

        self.assertEqual(item['id'], 'test')
        self.assertEqual(item['pychef_test_ver1'], 'secr3t c0d3')
        self.assertEqual(item['pychef_test_ver2'], '3ncrypt3d d@t@ b@g')

        # Incorrect IV should raise a decryption error
        item.raw_data['pychef_test_ver1']['iv'] = 'ZTM1MjY3OTc4ZjAwOTBlNw=='
        self.assertRaises(ChefDecryptionError, item.__getitem__, 'pychef_test_ver1')

        # Invalid HMAC should raise a decryption error
        item.raw_data['pychef_test_ver2']['hmac'] = 'v0lMrOmi1ZgA/vtfE2NZO2mO62LagIM2KCZSrWiO/8M='
        self.assertRaises(ChefDecryptionError, item.__getitem__, 'pychef_test_ver2')

    def test__set_item__(self):
        api = ChefAPI('https://chef_test:3000', os.path.join(TEST_ROOT, 'client.pem'), 'admin', secret_file=os.path.join(TEST_ROOT, 'encryption_key'))
        bag = DataBag('test_1')
        item = EncryptedDataBagItem(bag, 'test', api, True)
        item['id'] = 'test'
        api.encryption_version = 1
        item['pychef_test_ver1'] = 'secr3t c0d3'
        api.encryption_version = 2
        item['pychef_test_ver2'] = '3ncrypt3d d@t@ b@g'

        self.assertEqual(item['id'], 'test')

        self.assertIsInstance(item.raw_data['pychef_test_ver1'], dict)
        self.assertEqual(item.raw_data['pychef_test_ver1']['version'], 1)
        self.assertEqual(item.raw_data['pychef_test_ver1']['cipher'], 'aes-256-cbc')
        self.assertIsNotNone(item.raw_data['pychef_test_ver1']['iv'])
        self.assertIsNotNone(item.raw_data['pychef_test_ver1']['encrypted_data'])

        self.assertIsInstance(item.raw_data['pychef_test_ver2'], dict)
        self.assertEqual(item.raw_data['pychef_test_ver2']['version'], 2)
        self.assertEqual(item.raw_data['pychef_test_ver2']['cipher'], 'aes-256-cbc')
        self.assertIsNotNone(item.raw_data['pychef_test_ver2']['iv'])
        self.assertIsNotNone(item.raw_data['pychef_test_ver2']['hmac'])
        self.assertIsNotNone(item.raw_data['pychef_test_ver2']['encrypted_data'])

class EncryptedDataBagItemHelpersTestCase(ChefTestCase):
    def test_get_version(self):
        self.assertEqual(get_decryption_version({"version": "1"}), '1')
        self.assertEqual(get_decryption_version({"version": 1}), 1)
        self.assertEqual(get_decryption_version({"version": "2"}), '2')
        self.assertEqual(get_decryption_version({"version": 2}), 2)
        self.assertRaises(ChefUnsupportedEncryptionVersionError, get_decryption_version, {"version": 0})
        self.assertRaises(ChefUnsupportedEncryptionVersionError, get_decryption_version, {"version": "not a number"})

