import numpy as np
from binascii import hexlify, unhexlify

def to_bin(vec):
    num = int(''.join([str(x) for x in list(vec)]), 2)
    return unhexlify('{1:0{0}x}'.format(2, num))
    
def from_bin(binary):
    return np.array([int(x) for x in bin(int(hexlify(binary), 16))[2:]])

def get_vector(p, weight):
    coefficients = np.array([0] * (p - weight) + [1] * weight)
    np.random.shuffle(coefficients)
    return coefficients
    
def mul_poly(x, y):
    X = np.fft.rfft(x)
    Y = np.fft.rfft(y)
    return mul_fft(X, Y)

def mul_fft(X, Y):
    return np.array([int(np.round(x) % 2) for x in np.fft.irfft(X * Y).real])