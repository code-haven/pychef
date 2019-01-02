import os
import sys

from ctypes import *
from chef.rsa import _eay, SSLError

c_int_p = POINTER(c_int)

# void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a);
EVP_CIPHER_CTX_init = _eay.EVP_CIPHER_CTX_init
EVP_CIPHER_CTX_init.argtypes = [c_void_p]
EVP_CIPHER_CTX_init.restype = None

#int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
#        int *outl, unsigned char *in, int inl);
EVP_CipherUpdate = _eay.EVP_CipherUpdate
EVP_CipherUpdate.argtypes = [c_void_p, c_char_p, c_int_p, c_char_p, c_int]
EVP_CipherUpdate.restype = c_int

#int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *out,
#         int *outl);
EVP_CipherFinal = _eay.EVP_CipherFinal
EVP_CipherFinal.argtypes = [c_void_p, c_char_p, c_int_p]
EVP_CipherFinal.restype = c_int

#EVP_CIPHER *EVP_aes_256_cbc(void);
EVP_aes_256_cbc = _eay.EVP_aes_256_cbc
EVP_aes_256_cbc.argtypes = []
EVP_aes_256_cbc.restype = c_void_p

#EVP_MD *EVP_sha1(void);
EVP_sha1 = _eay.EVP_sha1
EVP_sha1.argtypes = []
EVP_sha1.restype = c_void_p

#int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
#        unsigned char *key, unsigned char *iv, int enc);
EVP_CipherInit = _eay.EVP_CipherInit
EVP_CipherInit.argtypes = [c_void_p, c_void_p, c_char_p, c_char_p, c_int]
EVP_CipherInit.restype = c_int

#int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *x, int padding);
EVP_CIPHER_CTX_set_padding = _eay.EVP_CIPHER_CTX_set_padding
EVP_CIPHER_CTX_set_padding.argtypes = [c_void_p, c_int]
EVP_CIPHER_CTX_set_padding.restype = c_int

# Structures required for ctypes

EVP_MAX_IV_LENGTH = 16
EVP_MAX_BLOCK_LENGTH = 32
AES_BLOCK_SIZE = 16

class EVP_CIPHER(Structure):
    _fields_ = [
            ("nid", c_int),
            ("block_size", c_int),
            ("key_len", c_int),
            ("iv_len", c_int),
            ("flags", c_ulong),
            ("init", c_voidp),
            ("do_cipher", c_voidp),
            ("cleanup", c_voidp),
            ("set_asn1_parameters", c_voidp),
            ("get_asn1_parameters", c_voidp),
            ("ctrl", c_voidp),
            ("app_data", c_voidp)
    ]

class EVP_CIPHER_CTX(Structure):
    _fields_ = [
            ("cipher", POINTER(EVP_CIPHER)),
            ("engine", c_voidp),
            ("encrypt", c_int),
            ("buflen", c_int),
            ("oiv", c_ubyte * EVP_MAX_IV_LENGTH),
            ("iv", c_ubyte * EVP_MAX_IV_LENGTH),
            ("buf", c_ubyte * EVP_MAX_BLOCK_LENGTH),
            ("num", c_int),
            ("app_data", c_voidp),
            ("key_len", c_int),
            ("flags", c_ulong),
            ("cipher_data", c_voidp),
            ("final_used", c_int),
            ("block_mask", c_int),
            ("final", c_ubyte * EVP_MAX_BLOCK_LENGTH) ]


class AES256Cipher(object):
    def __init__(self, key, iv, salt='12345678'):
        self.key_data = create_string_buffer(key)
        self.iv = create_string_buffer(iv)
        self.encryptor = self.decryptor = None
        self.salt = create_string_buffer(salt.encode('utf8'))

        self.encryptor = EVP_CIPHER_CTX()
        self._init_cipher(byref(self.encryptor), 1)

        self.decryptor = EVP_CIPHER_CTX()
        self._init_cipher(byref(self.decryptor), 0)

    def _init_cipher(self, ctypes_cipher, crypt_mode):
        """ crypt_mode parameter is a flag deciding whether the cipher should be
        used for encryption (1) or decryption (0)  """
        EVP_CIPHER_CTX_init(ctypes_cipher)
        EVP_CipherInit(ctypes_cipher, EVP_aes_256_cbc(), self.key_data, self.iv, c_int(crypt_mode))
        EVP_CIPHER_CTX_set_padding(ctypes_cipher, c_int(1))

    def _process_data(self, ctypes_cipher, data):
        # Guard against str passed in when using python3
        if sys.version_info[0] > 2 and isinstance(data, str):
            data = data.encode('utf8')
        length = c_int(len(data))
        buf_length = c_int(length.value + AES_BLOCK_SIZE)
        buf = create_string_buffer(buf_length.value)

        final_buf = create_string_buffer(AES_BLOCK_SIZE)
        final_length = c_int(0)

        EVP_CipherUpdate(ctypes_cipher, buf, byref(buf_length), create_string_buffer(data), length)
        EVP_CipherFinal(ctypes_cipher, final_buf, byref(final_length))

        return string_at(buf, buf_length) + string_at(final_buf, final_length)


    def encrypt(self, data):
        return self._process_data(byref(self.encryptor), data)

    def decrypt(self, data):
        return self._process_data(byref(self.decryptor), data)
