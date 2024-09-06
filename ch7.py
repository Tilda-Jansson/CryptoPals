from utils.AES import AESCipher
from utils.base64_to_byte import base64_to_byte

#Always operate on raw bytes
if __name__ == '__main__':
    ### 7.
    print("\n#### 7. ####")
    
    key = b"YELLOW SUBMARINE"
    aes = AESCipher(key)
    
    with open('texts/7.txt', 'r') as file:
        base64_encoded_data = file.read()
    base64_encoded_data = base64_encoded_data.replace('\n', '')
    ciphertext = base64_to_byte(base64_encoded_data)

    decrypted_message_aes = aes.decrypt(ciphertext, "ECB")

    with open("7decoded.txt", 'w') as file:
        file.write(decrypted_message_aes.decode("utf-8"))
