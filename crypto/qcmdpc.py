from operations.arithmetic import *
from operations.randomgen import *

from copy import copy

class McEliece:
    
    def __init__(self):
        self.randgen = RandomGenerator()
    
    def set_private_key(self, priv_key):
        self.H_0 = priv_key.H_0
        self.H_1 = priv_key.H_1
        
        self.G = mul_poly(priv_key.H_0, priv_key.H_1inv) # compute public key
        
        self.block_length = priv_key.block_length
        self.block_error = priv_key.block_error
        self.block_weight = priv_key.block_weight

    def get_public_key(self):
        pub_key = PublicKey()
        pub_key.set_params(self.G, self.block_error)
        return pub_key
    
    def encrypt(self, pub_key, m):
        v = (mul_poly(pub_key.G, m) + self.randgen.get_random_weight_vector( \
            pub_key.block_length, pub_key.block_error + self.randgen.flip_coin())) % 2
        u = (m + self.randgen.get_random_weight_vector(pub_key.block_length, \
            pub_key.block_error + self.randgen.flip_coin())) % 2
        return u, v

    def syndrome(self, c_0, c_1):
        return (mul_poly(self.H_0, c_0) + mul_poly(self.H_1, c_1)) % 2
    
    def decrypt(self, c_0, c_1):
        synd = self.syndrome(c_0, c_1)

        # compute correlations with syndrome
        H0_ind = np.nonzero(self.H_0)[0]
        H1_ind = np.nonzero(self.H_1)[0]

        unsat_H0 = np.zeros(self.block_length)
        for i in H0_ind:
            for j in range(len(synd)):
                if synd[j]: unsat_H0[(j-i) % self.block_length] += 1

        unsat_H1 = np.zeros(self.block_length)
        for i in H1_ind:
            for j in range(len(synd)):
                if synd[j]: unsat_H1[(j-i) % self.block_length] += 1
        
        rounds = 10
        delta = 5
        threshold = 100
        r = 0

        while True:
            max_unsat = max(unsat_H0.max(), unsat_H1.max())
            
            # if so, we are don
            if max_unsat == 0: 
                break
                
            # we have reach the upper bound on rounds
            if r >= rounds: 
                raise ValueError('Decryption error')
                break
            r += 1
            
            # update threshold
            if max_unsat > delta: threshold = max_unsat - delta
    
            round_unsat_H0 = copy(unsat_H0)
            round_unsat_H1 = copy(unsat_H1)
            
            # first block sweep
            for i in range(self.block_length):
                if round_unsat_H0[i] <= threshold: continue
        
                for j in H0_ind:
                    increase = (synd[(i+j) % self.block_length] == 0)
                    for k in H0_ind:
                        m = (i+j-k) % self.block_length
                        if increase:
                            unsat_H0[m] +=1
                        else:
                            unsat_H0[m] -=1
                    
                    for k in H1_ind:
                        m = (i+j-k) % self.block_length
                        if increase:
                            unsat_H1[m] +=1
                        else:
                            unsat_H1[m] -=1
                    
                    synd[(i+j) % self.block_length] ^= 1
            
                c_0[i] ^= 1
            
            # second block sweep
            for i in range(self.block_length):
                if round_unsat_H1[i] <= threshold: continue
        
                for j in H1_ind:
                    increase = (synd[(i+j) % self.block_length] == 0)
            
                    for k in H0_ind:
                        m = (i+j-k) % self.block_length
                        if increase:
                            unsat_H0[m] +=1
                        else:
                            unsat_H0[m] -=1
                    
                    for k in H1_ind:
                        m = (i+j-k) % self.block_length
                        if increase:
                            unsat_H1[m] +=1
                        else:
                            unsat_H1[m] -=1
                    
                    synd[(i+j) % self.block_length] ^= 1
            
                c_1[i] ^= 1
        return c_0