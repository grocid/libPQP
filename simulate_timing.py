import numpy as np
import time


from arithmetic import *
from private_key import *
from public_key import *
from qcmdpc import *
from keygen import *

keygen = Keygen()
priv_key, pub_key = keygen.generate()

cipher = McEliece()
cipher.set_private_key(priv_key)

timings = []

for i in range(0, 1000):
    print i
    start = time.time()
    randomized = get_vector(pub_key.block_length, 1600)
    a, b = cipher.encrypt(pub_key, randomized)
    r = cipher.decrypt(a, b)
    end = time.time()
    timings.append(end - start)
    if (randomized != r).all():
        print "FAIL"
        break

print timings
