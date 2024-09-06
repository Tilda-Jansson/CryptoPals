from utils.AES import AESCipher
import os
from utils.ch9 import pad

class UserProfileECB:
    def __init__(self):
        self.key = os.urandom(16)  # AES key for encryption/decryption
        self.aes = AESCipher(self.key)
        
    def parse(self, data: bytes):
        """Parse a k=v, e.g. foo=bar&baz=qux&zap=zazzle string into a dictionary."""
        string = data.decode()
        items = string.split('&')
        return {k:v for (k,v) in (item.split('=') for item in items)}
    
    def profile_for(self, email: bytes) -> bytes:
        """Encodes a user profile for a given email address. e.g.'email=foo@bar.com&uid=10&role=user' """
        if b"&" in email or b"=" in email:
            raise ValueError("Invalid email address") #Sanitize
        
        profile = {
            b"email": email,
            b"uid": b"10",
            b"role": b"user"
        }
        # Encoding the profile string
        profile_bytes = b'&'.join([k + b"=" + v for (k,v) in profile.items()])
        return profile_bytes
    
    def encode_and_encrypt_profile(self, email: bytes):
        encoded_profile = self.profile_for(email) #Encode
        encrypted_profile = self.aes.encrypt(encoded_profile, "ECB") 
        return encrypted_profile
        
    def decrypt_and_parse_profile(self, encrypted_profile: bytes):
        decrypted_profile = self.aes.decrypt(encrypted_profile, "ECB")
        return self.parse(decrypted_profile)
        

if __name__ == "__main__":
    profiler= UserProfileECB()

    email = b'foo@bar.com'   
    assert (profiler.profile_for(email) == b'email=foo@bar.com&uid=10&role=user')

    assert (profiler.parse(b'email=foo@bar.com&uid=10&role=user') == {'email': 'foo@bar.com', 'uid': '10', 'role': 'user'})

    encrypted_profile = profiler.encode_and_encrypt_profile(email)
    assert (profiler.decrypt_and_parse_profile(encrypted_profile) == {'email': 'foo@bar.com', 'uid': '10', 'role': 'user'})
    
    #### Attack:
    # Step 1
    email1 = b'A' * 13 
    
    # checking
    encoded_profile = profiler.profile_for(email1)
    blocks = [encoded_profile[i:i+16] for i in range(0, len(encoded_profile), 16)]
    print("blocks:", blocks)  # [b'email=AAAAAAAAAA', b'AAA&uid=10&role=', b'user']
    
    ciphertext1 = profiler.encode_and_encrypt_profile(email1)[:-16] # remove the padded user block
    print(len(ciphertext1)) # 32 bits
    
    # Step 2
    admin_padded = pad(b"admin", 16)  # Padding to make "admin" fit exactly into one block
    
    # Encrypt the admin_padded block by fitting it into an individual block in the encoded profile
    email2 = b'A' * (10) + admin_padded

    # checking that the admin padded block is in a separate block and extract it
    encoded_profile = profiler.profile_for(email2)
    blocks = [encoded_profile[i:i+16] for i in range(0, len(encoded_profile), 16)]
    print(blocks) # [b'email=AAAAAAAAAA', b'admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b', b'&uid=10&role=use', b'r']
    print(encoded_profile[16:2*16]) # b'admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'

    ciphertext2 = profiler.encode_and_encrypt_profile(email2)[16:2*16] # Extract the encrypted admin padded block 
    modified_encryption = ciphertext1 + ciphertext2 # put the ciphertexts together so that '...&role=admin'
    print(len(modified_encryption))
    
    print(profiler.decrypt_and_parse_profile(modified_encryption))