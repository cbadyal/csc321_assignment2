#assignment 2 part 2
#replace YA and YB with q
#Demonstrate how mallory can determine shared secret s 
#show mallory can decrypt c0 and c1

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad #just to check the result decryption
import hashlib
import random
from . import math_utils



def pad(message):
  padding_length = 16 - (len(message) % 16) #how much is left until 16 
  padding = bytes([padding_length] * padding_length)
  return message + padding

#agree on ietf 1024 bit params
q = 'B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371'
q_int = int(q, 16)

g = 'A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5'
g_int = int(g, 16)


#generate private keys -- using randint up until q_int 
XA = random.randint(1, q_int)
XB = random.randint(1, q_int)


YA = math_utils.mod_pow(g_int,XA,q_int)
YB = math_utils.mod_pow(g_int,XB,q_int)

#modify public keys -- set them equal to q
YA_modified = q_int
YB_modified = q_int

#exchange public keys
s_int = math_utils.mod_pow(YB,XA,q_int)
s_prime_int = math_utils.mod_pow(YA,XB,q_int)


s = str(s_int).encode('utf-8')#should this be equal to 0 bc it's not for me
s_prime = str(s_prime_int).encode('utf-8')



hash_object = hashlib.sha256(s).digest()#in bytes 
key_a = hash_object[:16] #key a for CBC
key_a_hex = hashlib.sha256(s).hexdigest()

hash_object = hashlib.sha256(s_prime).digest()#in bytes
key_b = hash_object[:16] #key b for CBC 
key_b_hex = hashlib.sha256(s_prime).hexdigest()

#mallory gets a key as well
hash_object = hashlib.sha256(s).digest()
key_m = hash_object[:16] #key b for CBC 
key_m_hex = hashlib.sha256(s).hexdigest()


message_a = "Hi Bob"
message_b = "Hi Alice"

#encrypt message from alice to bob
# generate shared iv 
iv = get_random_bytes(16)
iv_hex = ''.join([hex(x)[2:].zfill(2) for x in iv])
cipher_enc = AES.new(key_a, AES.MODE_CBC, iv)
message_a_bytes = message_a.encode('utf-8')
padded_message = pad(message_a_bytes)
ciphertext_a = cipher_enc.encrypt(padded_message) #alice's message in bytes 
c0 = ''.join([hex(x)[2:].zfill(2) for x in ciphertext_a])



#Decrypt message using mallory's key (intercepted)
cipher_dec = AES.new(key_m, AES.MODE_CBC, iv)
decrypted_message_a_intercept = unpad(cipher_dec.decrypt(ciphertext_a), 16, style="pkcs7")
decrypted_message_a_intercept = decrypted_message_a_intercept.decode('utf-8')

#Bob receives c0 and iv 
cipher_dec = AES.new(key_b, AES.MODE_CBC, iv)
decrypted_message_a = unpad(cipher_dec.decrypt(ciphertext_a), 16, style="pkcs7")
decrypted_message_a = decrypted_message_a.decode('utf-8')


#create message on Bob's end
message_b = "Hi Alice"

#encrypt message from Bob
cipher_enc = AES.new(key_b, AES.MODE_CBC, iv)
message_b_bytes = message_b.encode('utf-8')
padded_message = pad(message_b_bytes)
ciphertext_b = cipher_enc.encrypt(padded_message) #bob's message in bytes 
c1 = ''.join([hex(x)[2:].zfill(2) for x in ciphertext_a])

#receive encrypted message (intercepted)
cipher_dec = AES.new(key_m, AES.MODE_CBC, iv)
decrypted_message_b_intercept = unpad(cipher_dec.decrypt(ciphertext_b), 16, style="pkcs7")
decrypted_message_b_intercept = decrypted_message_b_intercept.decode('utf-8')

#Alice receives iv and c1
#Alice decrypts message 
cipher_dec = AES.new(key_a, AES.MODE_CBC, iv)
decrypted_message_b = unpad(cipher_dec.decrypt(ciphertext_b), 16, style="pkcs7")
decrypted_message_b = decrypted_message_b.decode('utf-8')



#print output
print("Diffie-Hellman Protocol (q and g as recommended by IETF)")
print("--------------------------------------------------------")
print("Alice's private key (XA):", XA)
print()
print("Alice's public key (YA):", YA)
print()
print("Bob's private key (XB):", XB)
print()
print("Bob's public key (YB):", YB)
print()
print("Modified YA (sent to Bob)", YA_modified)
print()
print("Modified YB (sent to Alice)", YB_modified)
print()
print("Alice's computed shared secret:", s_int)
print()
print("Bob's computed shared secred:", s_prime_int)
print()
print("Alice's derived key:", key_a_hex)
print()
print("Bob's derived key:", key_b_hex)
print()
print("Mallory's derived key:", key_m_hex)
print()
print("Mallory determines the shared secret (s):", s_int)#should this be s? bc we used modified ya and yb?
print()
print("All parties have the same key:", s==s_prime)#should we be calculating a separate s?
print()
print("Alice's message:", message_a)
print()
print("Alice's IV:", iv_hex)
print()
print("Alice's ciphertext:", c0)
print()
print("Mallory decrypts c0:", decrypted_message_a_intercept)
print()
print("Bob's message:", message_b)
print()
print("Bob's IV:", iv_hex)
print()
print("Bob's ciphertext:", c1)
print()
print("Mallory decrypts c1:", decrypted_message_b_intercept)