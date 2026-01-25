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

#sign and verify are like enc dec but the other way around with public/priv keys
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

print(rsa_verify(m3, s3, PU))#it works, just need to print everything
print("Demonstrating RSA Signature Malleability")
print("----------------------------------------")
print("Original message (m1): ", m1)
print()
print("Original message (m2): ", m2)
print()
print("Signature for m1:", s1)
print()
print("Signature for m2:", s2)
print()
print("Verify original signatures:")
print()
isValid = rsa_verify(m1, s1, PU)
print("Signature 1 is valid: ", isValid)
print()
isValid = rsa_verify(m2, s2, PU)
print("Signature 2 is valid:", isValid)
print()
print("Mallory's new message (m3 = m1 * m2 mod n):", m3)
print()
print("Mallory's forged signature for m3:")
print(s3)
print()
print("Verifying Mallory's forged signature:")
isValid = rsa_verify(m3, s3, PU)
print("Signature 3 is valid: ", isValid)
print()
print("Attack successful: Mallory created a valid signature for a new message!")


