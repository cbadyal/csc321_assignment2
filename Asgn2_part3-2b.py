from Crypto.Util import number
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from . import math_utils
import random
import hashlib

#generate p, q (primes)
p = number.getPrime(2048)
q = number.getPrime(2048)
e = 65537

n = p * q
phi = (p-1)*(q-1)
d = math_utils.mod_inverse(e, phi)


PU = (n, e) #public key
PR = (n, d) #private key

def rsa_sign(m_int, PR):
  n = PR[0]
  d = PR[1]
  
  if not (0 < m_int < n):
    print("message must be > n and < 0")
  return math_utils.mod_pow(m_int, d, n)

def rsa_verify(m_int, signature_int, PU):
  n = PU[0]
  e = PU[1]
  return math_utils.mod_pow(signature_int, e, n) == (m_int % n)

#choose 2 messages, m1 and m2 and sign them
m1 = random.randint(2, n-1)
m2 = random.randint(2, n-1)

s1 = rsa_sign(m1, PR)
s2 = rsa_sign(m2, PR)

m3 = (m1 * m2) % n
s3 = (s1 * s2) % n




