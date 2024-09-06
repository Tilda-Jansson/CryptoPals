from utils.AES import AESCipher
from utils.base64_to_byte import base64_to_byte

# CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)
#def decrypt_aes_cbc(ciphertext: bytes, key: bytes, IV: bytes) -> bytes:
    
#Always operate on raw bytes
if __name__ == '__main__':
    key = b"YELLOW SUBMARINE"
    aes = AESCipher(key)
    iv =  b"\x00" * aes.block_size
    
    with open('./texts/10.txt', 'r') as file:
        base64_ciphertext = file.read()

    # Decode the Base64-encoded ciphertext
    base64_ciphertext = base64_ciphertext.replace('\n', '')
    ciphertext = base64_to_byte(base64_ciphertext)
    
    decrypted_cbc = aes.decrypt(ciphertext, "CBC", iv)
    #print(f"CBC Decrypted: {text}")
    
    with open("10decoded.txt", 'w') as file:
        file.write(decrypted_cbc.decode("utf-8"))
