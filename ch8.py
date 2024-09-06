
def detect_ecb_encrypted_ciphertext(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    
    ecb_encrypted_text = []
    for line_number, hex_encoded_ciphertext in enumerate(lines):
        # Remove newline characters and decode hex to bytes
        ciphertext = bytes.fromhex(hex_encoded_ciphertext.strip())
        
        if len(ciphertext) % 16 != 0:
            raise Exception('ciphertext length is not a multiple of block size')
        
        # Divide the ciphertext into 16-byte (128-bit) blocks
        blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
        
        # If there are duplicate blocks, it might be ECB encrypted
        # antalet block är inte lika med antalet unika block -> duplicates
        if len(blocks) != len(set(blocks)):
            ecb_encrypted_text.append((line_number, hex_encoded_ciphertext))
    
    return ecb_encrypted_text


#Always operate on raw bytes
if __name__ == '__main__':
    print("#### 8. ####")
    ecb_encrypted_texts = detect_ecb_encrypted_ciphertext("texts/8.txt")
    for line_number, hex_encoded_ciphertext in ecb_encrypted_texts:
        print(f"Ciphertext {line_number + 1} might be ECB encrypted: {hex_encoded_ciphertext.strip()}")
        
        

    
