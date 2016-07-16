import numpy as np

from crypto.protocol import *

message = b'this is a really secret message that is padded with some random.'

# create a my_protocol wrapper object
my_protocol = Protocol()

# generate keypair
my_protocol.generate_keypair()

# encrypt and compute ciphertext / simulate sender
ciphertext = my_protocol.encrypt_message(message, my_protocol.pub_key)

# output the ciphertext
print ciphertext

# decrypt ciphertext / simulate receiver
message, verified = my_protocol.decrypt_message(ciphertext)

if verified:
    print 'Message: ', message
else:
    print 'Something has been tampered with!'

############################################################

#from attacks.distinguisher import *

# Distinguisher susceptibility
# https://grocid.net/2015/01/28/attack-on-prime-length-qc-mdpc/

#distinguisher = Distinguisher(priv_key.block_error, priv_key.block_weight)
#if distinguisher.distinguish(c_0) and distinguisher.distinguish(c_1):
#    print 'Both blocks distinguished'
