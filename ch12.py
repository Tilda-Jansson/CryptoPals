from ch11 import InterfaceEncryptionOracle, generate_random_aes_key, detect_ECB_CBC_mode
from utils.AES import AESCipher
from utils.base64_to_byte import base64_to_byte

class ECB_EncryptionOracle(InterfaceEncryptionOracle):
    def __init__(self):
        self.key = generate_random_aes_key()
        self.aes = AESCipher(self.key)
        self.unknown_byte_string = base64_to_byte('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
        
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data under a random key"""
        added_text = plaintext + self.unknown_byte_string
        
        ciphertext = self.aes.encrypt(added_text, "ECB")  
        return ciphertext
  
  
def find_block_size(oracle: type[InterfaceEncryptionOracle]) -> int:
    initial_len = len(oracle.encrypt(b'')) # initial length of ciphertext
    for i in range(1, 64):  # Assuming block size won't be larger than 64 bytes
        data = b'A' * i
        new_len = len(oracle.encrypt(data))
        if new_len != initial_len:
            return new_len - initial_len #The block size
    raise Exception("Block size could not be found")


def find_payload_length(oracle: type[InterfaceEncryptionOracle], block_size: int) -> int:
    prev_length = len(oracle.encrypt(b''))
    for i in range(block_size): # i is the number of 'pad-bytes' used
        length = len(oracle.encrypt(b'A'*i))
        if length != prev_length:
            return prev_length - i


# Assumed that you cannot access the unknown string directly
def decrypt_byte_by_byte(oracle: type[InterfaceEncryptionOracle], block_size: int) -> bytes:
    discovered_bytes = b''

    # Find the length of the unknown string
    unknown_string_length = find_payload_length(oracle, block_size)
    
    for i in range(unknown_string_length):
        block_number = (i // block_size) + 1
        
        # Create a series of 'A's + discovered_bytes that is one byte short of the block size, so last byte is the unknown one
        one_byte_short = b'A' * (block_size - (i % block_size) - 1)
                
        cipher_to_match = oracle.encrypt(one_byte_short)
        
        # Try every possible byte to find a match
        for byte in range(256):
            guess = one_byte_short + discovered_bytes + bytes([byte])
            guess_ciphertext = oracle.encrypt(guess)
            
            # compare the ciphertexts up & including the unknown byte
            if cipher_to_match[:block_number * block_size] == guess_ciphertext[:block_number * block_size]: 
                discovered_bytes += bytes([byte])
                break
    return discovered_bytes
    
    
    
def main():
    oracle = ECB_EncryptionOracle()

    if detect_ECB_CBC_mode(oracle) != "ECB":
        raise ValueError("Wrong detection")
    else:
        print("Oracle is using ECB mode.")
        
    block_size = find_block_size(oracle)
    print(f"Discovered block size: {block_size}")
    
    decrypted_string = decrypt_byte_by_byte(oracle, block_size).decode('utf-8')
    print(f"Decrypted string: {decrypted_string}")


if __name__ == '__main__':
    main()