from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad #just to check the result decryption
import hashlib



def pad(message):
  padding_length = 16 - (len(message) % 16) #how much is left until 16 
  padding = bytes([padding_length] * padding_length)
  return message + padding


q = 'B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371'
q_int = int(q, 16)

g = 'A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5'
g_int = int(g, 16)

#generate private keys
XA = 22
XB = 15

YA = pow(g_int,XA) % q_int
YB = pow(g_int,XB) % q_int

#exchange public keys
s = pow(YB,XA) % q_int
s_prime = pow(YA,XB) % q_int

print(s, s_prime)
print(s==s_prime)

s = str(s).encode('utf-8')
s_prime = str(s_prime).encode('utf-8')

hash_object = hashlib.sha256(s).digest()
key_a = hash_object[:16] #key a for CBC

hash_object = hashlib.sha256(s_prime).digest()
key_b = hash_object[:16] #key b for CBC 

message_a = "Hi Bob"
message_b = "Hi Alice"

#encrypt message from alice to bob 
iv_a = get_random_bytes(16)
cipher_enc = AES.new(key_a, AES.MODE_CBC, iv_a)
message_a_bytes = message_a.encode('utf-8')
padded_message = pad(message_a_bytes)
ciphertext_a = cipher_enc.encrypt(padded_message) #alice's message in bytes 

print("\n Alice's message ciphertext (hex):")
c0 = ''.join([hex(x)[2:].zfill(2) for x in ciphertext_a])
#print(c0)



#send encrypted message c0 and iv_alice 
#decrypt message on Bob's end

cipher_dec = AES.new(key_a, AES.MODE_CBC, iv_a)
decrypted_message_a = unpad(cipher_dec.decrypt(ciphertext_a), 16, style="pkcs7")
decrypted_message_a = decrypted_message_a.decode('utf-8')


print("Decrypted message from Alice,", decrypted_message_a)







