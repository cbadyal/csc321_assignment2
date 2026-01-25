#task 3
#generate p, q (primes)
from Crypto.Util import number
from . import math_utils

p = number.getPrime(2048)
q = number.getPrime(2048)
e = 65537

n = p * q
phi = (p-1)(q-1)
d = math_utils.mod_inverse(e, phi)

#Public Key: (n, e)
#Private Key: (n, d)

