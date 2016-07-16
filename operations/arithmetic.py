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
import pyfftw

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

def to_sparse_represenation(x):
    return x.nonzero()[0]
    
def sparse_factor_mul(x, y):
    result = np.zeros(mod, dtype=np.int)
    for index in y:
        result += np.roll(x, index)
    return result

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
            # precision does not allow us to stay in FFT domain
            # hence, interchanging ifft(fft).
            X = np.copy(fft_object(x))
            Y = np.copy(fft_object(y))
            y = np.round(fft_object_inv(X * Y).real).astype('int') % 2
            x = square_sparse_poly(x)
            n = (n - 1) / 2
    return np.array([int(np.round(x) % 2) for x in mul_poly(x, y)]) 



