import numpy as np
from base64 import b64encode, decodestring
from arithmetic import *
from private_key import *
from struct import *

class Keygen:
    
    def __init__(self):
        self.block_length = 4801
        self.rate = [1,2]
        
    def generate(self):
        priv_key = Privatekey()
        priv_key.H_0 = get_vector(self.block_length, 45)
        priv_key.H_1 = get_vector(self.block_length, 45)
        priv_key.H_1inv = exp_poly(priv_key.H_1, 2**1200 - 2)
        
        return priv_key
    
    def f_encode(self, data):
        return b64encode(np.packbits(data))
        
    def f_decode(self, data):
        return np.frombuffer(decodestring(data), dtype=np.int)
    
    def save_keypair(self, filename):
        priv_key = Privatekey()
        
        x = self.f_encode(priv_key.H_1inv)
        print self.f_decode(x)
        
        f = open(filename + '.private', 'w')
        f.write(self.f_encode(priv_key.H_0) + '\n')
        f.write(self.f_encode(priv_key.H_1) + '\n')
        f.write(self.f_encode(priv_key.H_1inv) + '\n')
        
        f = open(filename + '.public', 'w')
        f.write(self.f_encode(mul_poly(priv_key.H_0, priv_key.H_1inv)) + '\n')

    
    def read_private_key(filename):
        priv_key = Privatekey()
        
        f = open(filename + '.private', 'w')
        f.readline()
