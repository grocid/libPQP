import numpy as np

from Crypto.Cipher import AES
from hashlib import sha512, sha256

from arithmetic import *
from private_key import *
from qcmdpc import *

priv_key = Privatekey()
receiver_pkc_cipher = McEliece()
receiver_pkc_cipher.set_private_key(priv_key)

# compute public key
pub_key = receiver_pkc_cipher.get_public_key()

sender_pkc_cipher = McEliece()

saltA = b'this is just a salt'
saltB = b'this is another a salt'
ivSalt = b'third salt'
message = b'this is a really secret message that is padded with some random.'

############################################################

# SENDER SIDE

# generate random messge
tag = get_vector(pub_key.block_length, 1600)
secret = to_bin(tag, pub_key.block_length / 8)
keyA = sha256(str(secret) + saltA).digest() # just some conversion
keyB = sha256(str(secret) + saltB).digest()

sender_iv = sha512(str(secret) + ivSalt).digest()[0:16]
sender_symmetric = AES.new(keyA, AES.MODE_CBC, sender_iv)

mac = sha256(message + str(secret)).digest() # yeah, this is not a 'real' HMAC but...

c_0, c_1 = sender_pkc_cipher.encrypt(pub_key, tag)

# pack the data into ciphertext. 
# obviously, this must be done in a different manner for end result.
ciphertext = c_0, c_1, \
             sender_symmetric.encrypt(message), mac

############################################################

# RECEIVER END

rc_0, rc_1, symmetric_stream, mac = ciphertext

decrypted_secret = to_bin(receiver_pkc_cipher.decrypt(rc_0, rc_1), priv_key.block_length / 8)
decrypted_keyA = sha256(str(decrypted_secret) + saltA).digest() # just some conversion
decrypted_keyB = sha256(str(decrypted_secret) + saltB).digest()

decrypted_iv = sha512(str(decrypted_secret) + ivSalt).digest()[0:16]
decrypted_symmetric = AES.new(decrypted_keyA, AES.MODE_CBC, decrypted_iv)

decrypted_mac = sha256(message + str(decrypted_secret)).digest()

print "MESSAGE:       ", decrypted_symmetric.decrypt(symmetric_stream)
print "HMAC verified: ", mac == decrypted_mac

############################################################

