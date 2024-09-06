base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" #64 st

def base64_to_byte(base64_str: str) -> bytes:
    binary_str = ''
    for i in base64_str:
        if i == '=':
            break
        temp = ''
        temp += bin(base64_chars.index(i))[2:] #remove 0b
        
        temp = temp.zfill(6)
        binary_str += temp
        
    # discard 2 trailing bits from the bit string each time a '=' is encountered
    if base64_str[-1] == '=' and base64_str[-2] != '=' : # remove last 2 bits
        binary_str = binary_str[:-2] 
        return int(binary_str, 2).to_bytes(len(binary_str) // 8, byteorder='big')
        #return int(binary_str, 2).to_bytes(-(-len(binary_str) // 8), byteorder='big')

    elif base64_str[-2:] == '==': # remove last 4 bits
        binary_str = binary_str[:-4]
        return int(binary_str, 2).to_bytes(len(binary_str) // 8, byteorder='big') 
    
    return int(binary_str, 2).to_bytes(len(binary_str) // 8, byteorder='big')
        
       
if __name__ == '__main__':
    print(base64_to_byte('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK').decode())