import numpy as np
from base64 import b64encode, decodestring

from operations.arithmetic import *
from crypto.private_key import *
from crypto.public_key import *
from operations.randomgen import *

class Keygen:
    
    def __init__(self):
        self.block_length = 4801
        self.block_weight = 45
        self.block_error = 42
        
        self.rate = [1,2]
        self.randgen = RandomGenerator()
        
    def generate(self):
        # create keypair
        priv_key = PrivateKey()
        pub_key = PublicKey()
        
        # set private-key parameters
        priv_key.H_0 = self.randgen.get_random_weight_vector(self.block_length, self.block_weight)
        priv_key.H_1 = self.randgen.get_random_weight_vector(self.block_length, self.block_weight)
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
