from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad #just to check the result decryption
import hashlib
import random



def pad(message):
  padding_length = 16 - (len(message) % 16) #how much is left until 16 
  padding = bytes([padding_length] * padding_length)
  return message + padding


q_int = 37
g_int = 5



#generate private keys
XA = 8
XB = 15

YA = pow(g_int,XA) % q_int
YB = pow(g_int,XB) % q_int

#exchange public keys
s_int = pow(YB,XA) % q_int
s_prime_int = pow(YA,XB) % q_int


s = str(s_int).encode('utf-8')
s_prime = str(s_prime_int).encode('utf-8')

hash_object = hashlib.sha256(s).digest()#in bytes 
key_a = hash_object[:16] #key a for CBC
key_a_hex = hashlib.sha256(s).hexdigest()

hash_object = hashlib.sha256(s_prime).digest()#in bytes
key_b = hash_object[:16] #key b for CBC 
key_b_hex = hashlib.sha256(s_prime).hexdigest()

message_a = "Hi Bob"
message_b = "Hi Alice"

#encrypt message from alice to bob 
iv_a = get_random_bytes(16)
iv_a_hex = ''.join([hex(x)[2:].zfill(2) for x in iv_a])
cipher_enc = AES.new(key_a, AES.MODE_CBC, iv_a)
message_a_bytes = message_a.encode('utf-8')
padded_message = pad(message_a_bytes)
ciphertext_a = cipher_enc.encrypt(padded_message) #alice's message in bytes 
c0 = ''.join([hex(x)[2:].zfill(2) for x in ciphertext_a])




#Bob receives c0 and iv_alice 
#Decrypt message on Bob's end
cipher_dec = AES.new(key_a, AES.MODE_CBC, iv_a)
decrypted_message_a = unpad(cipher_dec.decrypt(ciphertext_a), 16, style="pkcs7")
decrypted_message_a = decrypted_message_a.decode('utf-8')


#create message on Bob's end
message_b = "Hi Alice"

#encrypt message from Bob
iv_b = get_random_bytes(16)
iv_b_hex = ''.join([hex(x)[2:].zfill(2) for x in iv_b])
cipher_enc = AES.new(key_b, AES.MODE_CBC, iv_b)
message_b_bytes = message_b.encode('utf-8')
padded_message = pad(message_b_bytes)
ciphertext_b = cipher_enc.encrypt(padded_message) #bob's message in bytes 
c1 = ''.join([hex(x)[2:].zfill(2) for x in ciphertext_a])



#Alice receives iv_b and c1
#Alice decrypts message 
cipher_dec = AES.new(key_b, AES.MODE_CBC, iv_b)
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
print("Alice's computed shared secret:", s_int)
print()
print("Bob's computed shared secred:", s_prime_int)
print()
print("Alice's derived key:", key_a_hex)
print()
print("Bob's derived key:", key_b_hex)
print()
print("Alice and Bob have the same key:", s==s_prime)
print()
print("Alice's message:", message_a)
print()
print("Alice's IV:", iv_a_hex)
print()
print("Alice's ciphertext:", c0)
print()
print("Bob's decrypted message:", decrypted_message_a)
print()
print("Bob's message:", message_b)
print()
print("Bob's IV:", iv_b_hex)
print()
print("Bob's ciphertext:", c1)
print()
print("Alice's decrypted message:", decrypted_message_b)




