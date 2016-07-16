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
