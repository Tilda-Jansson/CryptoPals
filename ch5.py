from utils.ch2 import xor

# Encrypts plaintext using a repeating-key XOR
def repeating_key_xor_encrypt(plaintext: bytes, key: bytes) -> bytes:
    # Extend the key to match the length of the plaintext
    extended_key = (key * ((len(plaintext) // len(key)) + 1))[:len(plaintext)]
    
    # Encrypt using XOR
    encrypted_bytes = xor(plaintext, extended_key)

    return encrypted_bytes

#Always operate on raw bytes
if __name__ == '__main__':
    print("#### 5. ####")
    plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = b"ICE"
    encrypted_bytes = repeating_key_xor_encrypt(plaintext, key)
    encrypted_hex = encrypted_bytes.hex()
    assert("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f" == encrypted_hex)
    print(encrypted_hex)