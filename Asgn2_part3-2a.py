#task 3 part 2a
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


def pad(message):
  padding_length = 16 - (len(message) % 16) #how much is left until 16 
  padding = bytes([padding_length] * padding_length)
  return message + padding

def RSA_encrypt_int(PU, m_int):
    n, e = PU
    if not (0 < m_int < n):
        print("m must be less than n and greater than 0")
        return
    return pow(m_int, e, n)


#alice encrypts a symmetric key as c = mod_pow(s(integer), e, n)
#mallory modifies c to become c * mod_pow(r(integer), e, n)
s = random.randint(1, n-1) #choosing a random int as our key and encrypting it (should we just use any int?)
c = RSA_encrypt_int(PU, s) #s^e mod n

#mallory modifies c (method 1: multiply c by an encrypted factor (r))
r = 2
c_prime = c * math_utils.mod_pow(r, e, n) % n 

#mallory modifies c (method 2: directly encrypt a chosen multiple of s)
s_prime = s * 2 #this is our chosen multiple of s 
c_alt = math_utils.mod_pow(s_prime, e, n)

#send c_prime or c_alt
#bob decrypts and gets s_prime from c_prime or c_alt
#if he gets it from c_alt it's a different s than the one Alice sent (it's a new secret key Mallory created)
#if he gets it from c_prime it's the original s that Alice sent
s_prime_c_prime = math_utils.mod_pow(c_prime, d, n)
s_prime_c_alt = math_utils.mod_pow(c_alt, d, n)


#mallory recovers s using s_prime
r_inv = math_utils.mod_inverse(r, n)
s_from_prime = (s_prime_c_prime * r_inv) % n


#use k=SHA256(s) to decrypt AES-CBC encrypted m
m = "hello world"


#deriving the key
s_bytes = str(s).encode("utf-8")
s_key = hashlib.sha256(s_bytes).digest()[:16]

#aes cbc encryption
iv = get_random_bytes(16)
cipher = AES.new(s_key, AES.MODE_CBC, iv)
message_bytes = m.encode("utf-8")
padded = pad(message_bytes)
ciphertext = cipher.encrypt(padded)
c0 = ciphertext #this is the message encrypted


#the altered key from method 2 is a multiple of the original key
#method 1 reveals the original key to mallory, so s would stay the same 
#for method 1, if bob wants to decrypt he uses s_prime which is s * r (wrong), he unknowingly decrypts to a multiple of s
#because it was a multiple of s, the key padding is off

#printing output
print("Demonstrating RSA Encryption Malleability")
print("-----------------------------------------")

print("Alice's original symmetric key (s):", s)
print()

print("Encrypted symmetric key (c)", c)
print()

print("Mallory's modified ciphertext (c')", c_prime)
print()

print()

print("Alternative malleability attack approach:")
print("Mallory's chosen s'", s_prime)
print()

print("Mallory's computed c'", c_alt)
print()

print("Value Alice decrypts to:", s_prime_c_alt)
if (s_prime_c_alt == (s * 2) % n):
  print("Alterative attack successful: Alice decrypted to Mallory's chosen value!")
  print()


#converting c0 from bytes to an int
c0_hex = ''.join(hex(x)[2:].zfill(2) for x in c0)
c0_int = int(c0_hex, 16)
print("Bob's encrypted message (c0):", c0_int)
print()

