from ch11 import InterfaceEncryptionOracle, generate_random_aes_key
from utils.AES import AESCipher
from utils.base64_to_byte import base64_to_byte
from os import urandom
from random import randint

class ECB_EncryptionOracle(InterfaceEncryptionOracle):
    def __init__(self):
        self.key = generate_random_aes_key()
        self.aes = AESCipher(self.key)
        self.unknown_string = base64_to_byte("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
        # the random prefix is generated once at the instanciation of the oracle, and stay the same accross all calls to the oracle
        self.prefix = urandom(randint(1, 100)) 
        
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data under a random key with random padding and mode"""
        added_text = self.prefix + plaintext + self.unknown_string
        ciphertext = self.aes.encrypt(added_text, "ECB")  
        return ciphertext




def find_block_size(oracle: type[InterfaceEncryptionOracle]) -> bytes:
    initial_len = len(oracle.encrypt(b'')) # prefix_plus_target_plus_padding
    for i in range(1, 64):  # Assuming block size won't be larger than 64 bytes
        new_len = len(oracle.encrypt(b'A' * i))
        if new_len != initial_len: #new block is added
            block_size = new_len - initial_len #The block size
            min_ptxt_to_align = i # min. A's to align to full blocks FYLLER PRECIS TILL JMNA BLOCK
            return block_size, initial_len, min_ptxt_to_align
    raise Exception("Block size could not be found")

def split_bytes_in_blocks(data: bytes, block_size: int):
    blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
    return blocks



def find_prefix_length(oracle: type[InterfaceEncryptionOracle], block_size: int) -> int:
    # Inject blocks of 'A's to see where the block repetition starts
    for padding in range(1, block_size * 3):
        test_input = b'A' * padding
        ciphertext = oracle.encrypt(test_input)
        blocks = split_bytes_in_blocks(ciphertext, block_size)

        # Look for two consecutive identical blocks
        for i in range(1, len(blocks) - 1): # i > 0, since first block is guaranteed to contain prefix
            if blocks[i] == blocks[i + 1]: 
                # Once found, calculate the prefix length
                # Adjust the calculation based on the padding used
                offset = (padding - 2 * block_size) # since the two identified consecutive blocks only consists of AAAA..
                prefix_size = (i * block_size) - offset # i's value is the block below the first 'AAA..' block
                return prefix_size

    raise Exception("Unable to determine prefix size")



def decrypt_byte_by_byte(oracle, prefix_length, block_size, target_size):
    pad_prefix = b'A' * (block_size - (prefix_length % block_size)) # pad prefix to full blocks
    discovered_bytes = b''

    unknown_string_length = target_size
    
    for i in range(unknown_string_length):
        block_number = ((i + prefix_length + len(pad_prefix))// block_size) + 1
        
        # Create a block of 'A's that is one/several byte(s) short of the block size, so last byte is the unknown one when adding the discovered bytes
        one_byte_short = b'A' * (block_size - (i % block_size) - 1)
                
        cipher_to_match = oracle.encrypt(pad_prefix + one_byte_short)
        
        # Try every possible byte to find a match
        for byte in range(256):
            guess = pad_prefix + one_byte_short + discovered_bytes + bytes([byte]) #last byte is unknown after adding our discovered
            guess_ciphertext = oracle.encrypt(guess)
            
            if cipher_to_match[:block_number * block_size] == guess_ciphertext[:block_number * block_size]:
                discovered_bytes += bytes([byte])
                break
    return discovered_bytes
        
        
def main():
    oracle = ECB_EncryptionOracle()
    block_size, prefix_plus_target_plus_padding, min_ptxt_to_align = find_block_size(oracle)
    
    #find block where prefix size
    prefix_length = find_prefix_length(oracle, block_size)
    print(prefix_length == len(oracle.prefix))
    
    # min_ptxt_to_align = padding
    target_size = prefix_plus_target_plus_padding - min_ptxt_to_align - prefix_length
    
    assert(target_size == len(base64_to_byte('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'))) 
    
    print(decrypt_byte_by_byte(oracle, prefix_length, block_size, target_size).decode('utf-8'))

if __name__ == '__main__':
    main()