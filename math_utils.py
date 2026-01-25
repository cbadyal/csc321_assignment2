#util file 
import random
from math import gcd

def mod_pow(base, exponent, modulus):
    result = 1
    base %= modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent >>= 1
        base = (base * base) % modulus
    return result



def mod_inverse(a, m):
   def egcd(a, b):
      if a == 0: return (b, 0, 1)
      else:
          g, y, x = egcd(b % a, a)
          return (g, x - (b //a) * y, y)
   g, x, _ = egcd(a, m)
   if g != 1: raise Exception('Modular inverse does not exist')
   else: return x % m

def ascii_to_int(m):
   m = m.encode("ascii")
   h = m.hex()
   i = int(h, 16)
   return i

def int_to_ascii(m):
    h = hex(m)[2:] #removes the 0x prefix
    if len(h) % 2 == 1:
       h = "0" + h #pad it if it's something like 0x4 
    b = bytes.fromhex(h)
    s = b.decode("ascii")
    return s
    
    


   