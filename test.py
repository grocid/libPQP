import numpy as np

from Crypto.Cipher import AES
from hashlib import sha512, sha256

from arithmetic import *
from private_key import *
from qcmdpc import *
from keygen import *

class Protocol:
    
    def __init__(self):
        keygen = Keygen()
        self.priv_key = keygen.generate()
        self.receiver_pkc_cipher = McEliece()
        self.receiver_pkc_cipher.set_private_key(self.priv_key)

        # compute public key
        self.pub_key = self.receiver_pkc_cipher.get_public_key()

        self.sender_pkc_cipher = McEliece()

        self.saltA = b'this is just a salt'
        self.saltB = b'this is another a salt'
        self.ivSalt = b'third salt'
    
    def encrypt_message(self, message):
        # generate random data
        randomized = get_vector(self.pub_key.block_length, 1600)
        token = to_bin(randomized, self.pub_key.block_length / 8)
        keyA = sha256(str(token) + self.saltA).digest() # just some conversion
        keyB = sha256(str(token) + self.saltB).digest()

        sender_iv = sha512(str(token) + self.ivSalt).digest()[0:16]
        sender_symmetric = AES.new(keyA, AES.MODE_CBC, sender_iv)

        mac = sha256(message + str(token)).digest() # yeah, this is not a 'real' HMAC but...

        c_0, c_1 = self.sender_pkc_cipher.encrypt(self.pub_key, randomized)

        # pack the data into ciphertext. 
        # obviously, this must be done in a different manner for end result.
        ciphertext = c_0, c_1, \
                     sender_symmetric.encrypt(message), mac
        return ciphertext
    
    def decrypt_message(self, ciphertext):
        rc_0, rc_1, symmetric_stream, mac = ciphertext

        decrypted_token = to_bin(self.receiver_pkc_cipher.decrypt(rc_0, rc_1), self.priv_key.block_length / 8)
        decrypted_keyA = sha256(str(decrypted_token) + self.saltA).digest() # just some conversion
        decrypted_keyB = sha256(str(decrypted_token) + self.saltB).digest()

        decrypted_iv = sha512(str(decrypted_token) + self.ivSalt).digest()[0:16]
        receiver_symmetric = AES.new(decrypted_keyA, AES.MODE_CBC, decrypted_iv)
        decrypted_message = receiver_symmetric.decrypt(symmetric_stream)

        decrypted_mac = sha256(decrypted_message + str(decrypted_token)).digest()

        return decrypted_message, mac == decrypted_mac


message = b'this is a really secret message that is padded with some random.'

protocol_test = Protocol()
ciphertext = protocol_test.encrypt_message(message)
message, verified = protocol_test.decrypt_message(ciphertext)

if verified:
    print 'Message: ', message
else:
    print 'Something has been tampered with!'
############################################################

#from distinguisher import *

# Distinguisher susceptibility
# https://grocid.net/2015/01/28/attack-on-prime-length-qc-mdpc/

#distinguisher = Distinguisher(priv_key.block_error, priv_key.block_weight)
#if distinguisher.distinguish(c_0) and distinguisher.distinguish(c_1):
#    print 'Both blocks distinguished'


