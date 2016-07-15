import numpy as np
import pyfftw

from binascii import hexlify
from copy import copy

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

def div_poly(x, y):
    D = np.fft.rfft(np.array(list(y) + [0] * (len(x) - len(y))))
    conjugate = np.conj(D)
    result = np.fft.irfft(np.fft.rfft(x) * conjugate / (D * conjugate))
    return np.array([int(np.round(x) % 2) for x in result.real])

def shift_poly(x, n):
    return np.hstack((np.zeros(n, dtype=np.int), x[:-n]))

def fftw_(x):
    a = pyfftw.empty_aligned(len(x), dtype='complex128')
    b = pyfftw.empty_aligned(len(x), dtype='complex128')
    fft_object = pyfftw.FFTW(a, b)
    X = fft_object(x)
    return X

def ifftw_(x):
    a = pyfftw.empty_aligned(len(x), dtype='complex128')
    b = pyfftw.empty_aligned(len(x), dtype='complex128')
    fft_object = pyfftw.FFTW(a, b, direction='FFTW_BACKWARD')
    X = fft_object(x)
    return X
    
def mul_poly(x, y):
    X = fftw_(x)
    Y = fftw_(y)
    return np.round(ifftw_(X * Y).real).astype('int') % 2

def square_sparse_poly(x, times=1):
    indices = x.nonzero()[0]
    mod = len(x)
    indices *= pow(2, times, mod)
    result = np.zeros(mod, dtype=np.int)
    for index in indices: result[index % mod] ^= 1
    return result

def exp_poly(x, n):
    y = np.zeros(len(x), dtype=np.int)
    y[0] = 1
    
    a = pyfftw.empty_aligned(len(x), dtype='complex128')
    b = pyfftw.empty_aligned(len(x), dtype='complex128')
    fft_object = pyfftw.FFTW(a, b)
    fft_object_inv = pyfftw.FFTW(a, b, direction='FFTW_BACKWARD')
    
    while n > 1:
        if n % 2 == 0:
            x = square_sparse_poly(x)
            n = n / 2
        else:
            X = copy(fft_object(x))
            Y = copy(fft_object(y))
            y = np.round(fft_object_inv(X * Y).real).astype('int') % 2
            x = square_sparse_poly(x)
            n = (n - 1) / 2
    return np.array([int(np.round(x) % 2) for x in mul_poly(x, y)]) 



