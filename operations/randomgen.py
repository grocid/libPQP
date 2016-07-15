import numpy as np

from random import SystemRandom

class RandomGenerator:
    
    def __init__(self):
        self.gen = SystemRandom()

    def get_random_vector(self, length):
        random_vector = np.array([self.gen.randrange(2) for i in range(length)])
        return random_vector
    
    def get_random_weight_vector(self, length, weight):
        random_indices = set([self.gen.randrange(length) for i in range(weight)])
        
        while len(random_indices) < weight:
            random_indices.update([self.gen.randrange(length)])
        
        random_vector = np.zeros(length, dtype='int')
        random_vector[list(random_indices)] = 1
        
        return random_vector
    
    def flip_coin(self):
        return self.gen.randrange(2)
