import numpy as np
from base64 import b64encode, decodestring
from arithmetic import *
from private_key import *
from public_key import *
from struct import *

class Keygen:
    
    def __init__(self):
        self.block_length = 4801
        self.block_weight = 45
        self.block_error = 42
        
        self.rate = [1,2]
        
    def generate(self):
        # create keypair
        priv_key = PrivateKey()
        pub_key = PublicKey()
        
        # set private-key parameters
        priv_key.H_0 = get_vector(self.block_length, self.block_weight)
        priv_key.H_1 = get_vector(self.block_length, self.block_weight)
        priv_key.H_1inv = exp_poly(priv_key.H_1, 2**1200 - 2)
        
        priv_key.block_length = self.block_length
        priv_key.block_weight = self.block_weight
        priv_key.block_error = self.block_error
        
        # set public-key parameters
        pub_key.G = mul_poly(priv_key.H_0, priv_key.H_1inv)
        
        pub_key.block_length = self.block_length
        pub_key.block_weight = self.block_weight
        pub_key.block_error = self.block_error
        
        return priv_key, pub_key
    
    def f_encode(self, data):
        return b64encode(np.packbits(data))
        
    def f_decode(self, data):
        return np.frombuffer(decodestring(data), dtype=np.int)
    
    def save_keypair(self, filename):
        priv_key = PrivateKey()
        
        x = self.f_encode(priv_key.H_1inv)
        print self.f_decode(x)
        
        f = open(filename + '.private', 'w')
        f.write(self.f_encode(priv_key.H_0) + '\n')
        f.write(self.f_encode(priv_key.H_1) + '\n')
        f.write(self.f_encode(priv_key.H_1inv) + '\n')
        
        f = open(filename + '.public', 'w')
        f.write(self.f_encode(mul_poly(priv_key.H_0, priv_key.H_1inv)) + '\n')

    
    def read_private_key(filename):
        priv_key = PrivateKey()
        
        f = open(filename + '.private', 'w')
        f.readline()
