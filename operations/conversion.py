import numpy as np

from binascii import hexlify

def to_bin(vec, length):
    num = int(''.join([str(x) for x in list(vec)]), 2)
    return ('%%0%dx' % (length << 1) % num).decode('hex')[-length:] # libnum
    
def from_bin(binary):
    return np.array([int(x) for x in bin(int(hexlify(binary), 16))[2:]])
    
def to_int(vec):
    s = ''.join(str(x) for x in vec[::-1])
    return int(s, 2)

def from_int(num):
    return np.array([int(x) for x in bin(num)[2:]][::-1])