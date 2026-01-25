#task 3
#generate p, q (primes)
from Crypto.Util import number
from . import math_utils

p = number.getPrime(2048)
q = number.getPrime(2048)
e = 65537

n = p * q
phi = (p-1)*(q-1)
d = math_utils.mod_inverse(e, phi)


PU = (n, e) #public key
PR = (n, d) #private key

def RSA_encrypt(PU, msg):#takes in the public and private keys and encrypts
  n = PU[0]
  e = PU[1]

  msg_int = math_utils.ascii_to_int(msg)#integer we are encrypting
  if (msg_int > n):
    print("Error: integer message is too long")
    return
  c = math_utils.mod_pow(msg_int, e, n)
  return c
def RSA_decrypt(PR, c):
  n = PR[0]
  d = PR[1]
  msg_dec = math_utils.mod_pow(c, d, n)
  return msg_dec



#printing output
messages = ["Hello, World!", "Cryptography is fun!", "Test message for RSA"]
no_fail = 1
for m in messages:
  print("Original message: ", m)
  enc_m = RSA_encrypt(PU, m)
  print("Encrypted (integer): ", enc_m)
  dec_m = math_utils.int_to_ascii(RSA_decrypt(PR, enc_m))
  print("Decrypted: ", dec_m)
  if (m != dec_m):
    no_fail = 0

if(no_fail == 1):
  print("All valid messages were successfully encrypted and decrypted")







