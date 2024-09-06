# Manual base64 encoding without using the base64 library for the conversion

# Base64 character set
base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" #64 st

def hex_to_base64(hex_str: str) -> str:
    # Convert hex to binary
    binary_str = bin(int(hex_str, 16))[2:] #remove 0b

    # Base64 is meant to encode bytes (8 bit)
    # Make sure we have bytes
    binary_str = binary_str.zfill(len(binary_str)+ ((8-len(binary_str) % 8) if len(binary_str) % 8 != 0 else 0))
    
    # Make sure it is a multiple of 6. If we have a partial 6-bit chunk then fill it out with zeros
    binary_str = binary_str + '0' * (6-len(binary_str) % 6 if len(binary_str) % 6 != 0 else 0)
    
    # Split the binary string into 6-bit chunks
    chunks = [binary_str[i:i+6] for i in range(0, len(binary_str), 6)]
    
    # Convert each chunk to a base64 character
    base64_str = ''.join(base64_chars[int(chunk, 2)] for chunk in chunks)
    
    # Add padding to make the base64 string length a multiple of 4 chars
    while len(base64_str) % 4 != 0:
        base64_str += '='
    
    return base64_str


def base64_to_hex(base64_str: str) -> str:
    binary_str = ''
    for i in base64_str:
        if i == '=':
            break
        temp = ''
        temp += bin(base64_chars.index(i))[2:] #remove 0b
        
        temp = temp.zfill(6)
        binary_str += temp
        
    #print(binary_str)
    # discard 2 trailing bits from the bit string each time a '=' is encountered
    if base64_str[-1] == '=' and base64_str[-2] != '=' : # remove last 2 bits, one '='
        binary_str = binary_str[:-2] 
        return hex(int(binary_str, 2))[2:] #remove 0x

    elif base64_str[-2:] == '==': # remove last 4 bits, two '='
        binary_str = binary_str[:-4]
        return hex(int(binary_str, 2))[2:]
    
    return hex(int(binary_str, 2))[2:] # No padding used, was already a multiple of 4 characters
        

#Always operate on raw bytes
if __name__ == '__main__':
    # Convert the given hex string to base64 manually
    assert(hex_to_base64("4d616e") == 'TWFu')
    assert(hex_to_base64("4d61") == 'TWE=')
    assert(hex_to_base64("4d") == 'TQ==')
    assert(hex_to_base64("4") == 'BA==')
    assert(hex_to_base64("4A") == 'Sg==')
    assert(hex_to_base64("411") == 'BBE=')
    assert(hex_to_base64('4111111') == 'BBEREQ==')
    assert(hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
    
    assert(base64_to_hex('BA==') == '4')
    assert(base64_to_hex('BBE=') == '411')
    assert(base64_to_hex('SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t') == '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')