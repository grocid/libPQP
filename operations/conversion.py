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

from binascii import hexlify
from hashlib import sha512

def to_bin(vec, length):
    num = int(''.join([str(x) for x in list(vec)]), 2)
    return ('%%0%dx' % (length << 1) % num).decode('hex')[-length:] # libnum
    
def from_bin(binary):
    return np.array([int(x) for x in bin(int(hexlify(binary), 16))[2:]])

# just some packing operation
def pack(vec):
    return sha512(''.join([str(x) for x in list(vec)])).digest()
    
def to_int(vec):
    s = ''.join(str(x) for x in vec[::-1])
    return int(s, 2)

def from_int(num):
    return np.array([int(x) for x in bin(num)[2:]][::-1])