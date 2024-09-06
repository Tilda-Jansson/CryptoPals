from utils.ch2 import xor
from utils.score import score_text

def single_byte_xor_cipher(cipher_text: bytes) -> (bytes, int):
    best_score = 0
    decrypted_text = None
    found_key = None
    
    # Try XOR with every possible 8-bit value to find the key (0-255), includes the ASCII character set (0-127)
    for key in range(pow(2,8)):
        # XOR the cipher_text with the key
        extended_key =  bytes([key] * len(cipher_text))
    
        # Encrypt using XOR
        xored_text = xor(cipher_text, extended_key)
        
        # Score the result
        current_score = score_text(xored_text)
        
        # Update best score, decrypted text, and key if current is better
        if best_score < current_score:
            best_score = current_score
            decrypted_text = xored_text
            found_key = key
    
    return decrypted_text, found_key


#Always operate on raw bytes
if __name__ == '__main__':
    print("#### 3. ####")
    hex_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    data = bytes.fromhex(hex_str)
    decrypted_text, key = single_byte_xor_cipher(data)
    print("Decrypted Text:", decrypted_text.decode())
    print("Key:", str(key))
    print("key:", chr(key)) # returns the character the 'key' code point represents