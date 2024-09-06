from utils.AES import AESCipher
import os
from utils.ch2 import xor
from ch11 import InterfaceEncryptionOracle

class Oracle(InterfaceEncryptionOracle):
    def __init__(self):
        self.key = os.urandom(16)
        self.aes = AESCipher(self.key)
        self.iv = os.urandom(16)

    def encrypt(self, plaintext: bytes) -> bytes:
        # Escape semicolons (;) and equals signs (=) by prefixing them with a backslash (\), so they're treated as regular data
        quoted = plaintext.replace(b";", b"\\;").replace(b"=", b"\\=")
        
        prefix = b"comment1=cooking%20MCs;userdata="
        postfix = b";comment2=%20like%20a%20pound%20of%20bacon"
        full_data = prefix + quoted + postfix
        
        return self.aes.encrypt(full_data, 'CBC', self.iv) # includes padding already(!!)
        
        
    def decrypt_check_admin(self, ciphertext: bytes) -> bool:
        plaintext = self.aes.decrypt(ciphertext, 'CBC', self.iv)
        
        if b";admin=true;" in plaintext:
            return True
        else:
            return False
        
        

def main():
    
    prefix = b"comment1=cooking%20MCs;userdata="
    print(len(prefix)) # 32, precisely 2 blocks

    blocks = [prefix[i:i+16] for i in range(0, len(prefix), 16)]
    print(blocks)
    
    oracle = Oracle()

    test = oracle.encrypt(b"hi")
    print("TEST_decrypted:", oracle.aes.decrypt(test, 'CBC', oracle.iv)) # user input starts at beginning of a block, followed by ';' -> only need “;admin=true”
    #print("admin:", oracle.is_admin(test))

    # test
    c = bytearray(oracle.encrypt(b"xxxx"))
    c[16] = c[16] ^ 0x11 # bit flipping in block 2 affects bits in block 3
    print("decrypted:", oracle.aes.decrypt(bytes(c), 'CBC', oracle.iv))
     
    placeholder_size = len(b";admin=true") # 11
    ctxt = bytearray(oracle.encrypt(b'X'*placeholder_size))  # 3rd block
    
    # placeholder_size = 11, change previous 2nd ciphertext block
    ctxt[16:27] = xor(ctxt[16:27], b'X'*placeholder_size)
    ctxt[16:27] = xor(ctxt[16:27], b";admin=true")
    
    print("decrypted:", oracle.aes.decrypt(bytes(ctxt), 'CBC', oracle.iv))
    print(oracle.decrypt_check_admin(bytes(ctxt)))
    

if __name__ == '__main__':
    main()