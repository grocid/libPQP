from arithmetic import *
from copy import copy

block_length = 4800 # this is insecure, but OK for tests 
block_weight = 45
block_error = 42

p = 4800 # insecure, obviously but for the sake of FFT

class McEliece:
    
    def set_private_key(self, H_0, H_1, H_1inv):
        self.H_0 = H_0
        self.H_1 = H_1
        self.G = mul_poly(H_0, H_1inv) # compute public key

    def get_public_key(self):
        return self.G
    
    def encrypt(self, G, m):
        v = (mul_poly(G, m) + get_vector(block_length, block_error)) % 2
        u = (m + get_vector(block_length, block_error)) % 2
        return u,v

    def syndrome(self, H_0, H_1, c_0, c_1):
        return (mul_poly(H_0, c_0) + mul_poly(H_1, c_1)) % 2
    
    def decrypt(self,c_0, c_1):
    
        synd = self.syndrome(self.H_0, self.H_1, c_0, c_1)

        # compute correlations with syndrome

        H0_ind = np.nonzero(self.H_0)[0]
        H1_ind = np.nonzero(self.H_1)[0]

        unsat_H0 = np.zeros(block_length)
        for i in H0_ind:
            for j in range(len(synd)):
                if synd[j]: unsat_H0[(j-i) % block_length] += 1

        unsat_H1 = np.zeros(block_length)
        for i in H1_ind:
            for j in range(len(synd)):
                if synd[j]: unsat_H1[(j-i) % block_length] += 1
        
        rounds = 10
        delta = 5
        threshold = 100
        r = 0

        while True:
            max_unsat = max(unsat_H0.max(), unsat_H1.max())
    
            if max_unsat == 0: 
                break
        
            if r >= rounds: 
                raise ValueError('Decryption error')
                break
            r += 1
    
            if max_unsat > delta: threshold = max_unsat - delta
    
            round_unsat_H0 = copy(unsat_H0)
            round_unsat_H1 = copy(unsat_H1)
    
            for i in range(block_length):
                if round_unsat_H0[i] <= threshold: continue
        
                for j in H0_ind:
                    increase = (synd[(i+j) % block_length] == 0)
                    for k in H0_ind:
                        m = (i+j-k) % block_length
                        if increase:
                            unsat_H0[m] +=1
                        else:
                            unsat_H0[m] -=1
                    
                    for k in H1_ind:
                        m = (i+j-k) % block_length
                        if increase:
                            unsat_H1[m] +=1
                        else:
                            unsat_H1[m] -=1
                    
                    synd[(i+j) % block_length] ^= 1
            
                c_0[i] ^= 1

            for i in range(block_length):
                if round_unsat_H1[i] <= threshold: continue
        
                for j in H1_ind:
                    increase = (synd[(i+j) % block_length] == 0)
            
                    for k in H0_ind:
                        m = (i+j-k) % block_length
                        if increase:
                            unsat_H0[m] +=1
                        else:
                            unsat_H0[m] -=1
                    
                    for k in H1_ind:
                        m = (i+j-k) % block_length
                        if increase:
                            unsat_H1[m] +=1
                        else:
                            unsat_H1[m] -=1
                    
                    synd[(i+j) % block_length] ^= 1
            
                c_1[i] ^= 1
        return c_0