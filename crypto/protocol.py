'''
This file is part of libPQP
Copyright (C) 2016 Carl Londahl <carl.londahl@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import numpy as np

from Crypto.Cipher import AES
from hashlib import sha512, sha256

from operations.arithmetic import *
from operations.conversion import *
from operations.keyio import *

from crypto.private_key import *
from crypto.public_key import *
from crypto.qcmdpc import *
from crypto.keygen import *


class Protocol:
    
    def __init__(self):
        # instantiate primitives
        self.asymmetric_cipher = McEliece()        
        self.randgen = RandomGenerator()
        self.io = IO()
        
        # just some random salts
        self.saltA = b'this is just a salt'
        self.saltB = b'this is another a salt'
        self.ivSalt = b'third salt'
    
    def generate_keypair(self):
        # instantiate keygenerator and set keypair
        keygen = Keygen()
        self.priv_key, self.pub_key = keygen.generate()
        self.asymmetric_cipher.set_private_key(self.priv_key)
    
    def load_private_key(self, filename):
        f = open(filename, 'r')
        key = io.extract_der_priv_key(f.read())
        self.priv_key = key
        
    def save_keypair(self):
        return
        
    def generate_mac(self, message, token, key):
        return sha256(message + str(token) + key).digest()
    
    def symmetric_cipher_enc(self, message, mac, key, iv):
        symmetric_cipher = AES.new(key, AES.MODE_CBC, iv)
        return symmetric_cipher.encrypt(message + mac)
    
    def symmetric_cipher_dec(self, ciphertext, key, iv):
        symmetric_cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = symmetric_cipher.decrypt(ciphertext)
        mac = decrypted[-32:]
        message = decrypted[:-32]
        return message, mac
        
    def encrypt_message(self, message, recv_pub_key):
        # generate random data
        randomized = self.randgen.get_random_vector(self.pub_key.block_length)
        token = to_bin(randomized, (self.pub_key.block_length + 1) / 8)
        
        # derive keys
        keyA = sha256(str(token) + self.saltA).digest() # just some conversion
        keyB = sha256(str(token) + self.saltB).digest()
        
        # derive iv
        iv = sha512(str(token) + self.ivSalt).digest()[0:16]
        
        # generate mac
        mac = self.generate_mac(message, token, keyB)
        
        c_0, c_1 = self.asymmetric_cipher.encrypt(recv_pub_key, randomized)
        
        # generate ciphertext
        return self.io.get_der_ciphertext(c_0, c_1, \
               self.symmetric_cipher_enc(message, mac, keyA, iv))
    
    def decrypt_message(self, ciphertext):
        rc_0, rc_1, symmetric_stream = self.io.extract_der_ciphertext(ciphertext)
        
        # decrypt necessary data
        decrypted_token = to_bin(self.asymmetric_cipher.decrypt(rc_0, rc_1), \
                          (self.priv_key.block_length + 1) / 8)
        
        # derive keys from data
        decrypted_keyA = sha256(str(decrypted_token) + self.saltA).digest() # just some conversion
        decrypted_keyB = sha256(str(decrypted_token) + self.saltB).digest()
        
        # derive iv
        decrypted_iv = sha512(str(decrypted_token) + self.ivSalt).digest()[0:16]
        
        # decrypt ciphertext and derive mac
        decrypted_message, decrypted_mac = self.symmetric_cipher_dec(symmetric_stream, \
                                           decrypted_keyA, decrypted_iv)

        receiver_mac = self.generate_mac(decrypted_message, decrypted_token, decrypted_keyB)

        return decrypted_message, receiver_mac == decrypted_mac

