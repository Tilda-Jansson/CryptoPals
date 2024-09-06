import os
import random
from utils.AES import AESCipher

# generate a random AES key (16 random bytes)
def generate_random_aes_key():
    return os.urandom(16)

# Interface (so functions can be used with different types of oracles)
class InterfaceEncryptionOracle:
    def encrypt(self, plaintext: bytes) -> bytes:
        pass

# Class extending the interface
class randomEncryptionOracle(InterfaceEncryptionOracle):
    def __init__(self):
        self.key = generate_random_aes_key()
        self.iv = os.urandom(16)
        self.aes = AESCipher(self.key)
        self.used_modes = [] #for testing
        
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data under a random key with random padding and mode."""
        # Generate random padding
        prepend_padding = os.urandom(random.randint(5, 10)) # random bytes string 
        append_padding = os.urandom(random.randint(5, 10))
        padded_plaintext = prepend_padding + plaintext + append_padding
        
        # choose mode randomly
        if random.randint(0,1) == 0:
            mode = "ECB"
            ciphertext = self.aes.encrypt(padded_plaintext, "ECB")
        else:
            mode = "CBC"
            ciphertext = self.aes.encrypt(padded_plaintext, "CBC", self.iv)
        
        self.used_modes.append(mode)
        
        return ciphertext


# the plaintext is only for testing
def detect_ECB_CBC_mode(encryption_oracle: type[InterfaceEncryptionOracle], plaintext: bytes = b'A'*48) -> str:
    """Detect the block cipher mode used for encryption."""
    ciphertext = encryption_oracle.encrypt(plaintext)
    block_size = 16

    # Split ciphertext into blocks
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    
    # If there are duplicate blocks, it's likely ECB
    if len(blocks) != len(set(blocks)):
        return "ECB"
    else:
        return "CBC"
    
if __name__ == '__main__':
    oracle = randomEncryptionOracle()
    res_modes = []
    for _ in range(100):
        res_modes.append(detect_ECB_CBC_mode(oracle))
        
    compare = [i for (i, j) in zip(oracle.used_modes, res_modes) if i == j] 
    print(len(compare))