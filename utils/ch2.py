# takes two equal-length buffers and produces their XOR combination
def xor(buffer1: bytes, buffer2: bytes) -> bytes:
    # Ensure the buffers are of equal length
    if len(buffer1) != len(buffer2):
        raise ValueError("Buffers must be of equal length.")
    
    # Perform bitwise XOR operation byte by byte
    xor_result = bytes([b1 ^ b2 for b1, b2 in zip(buffer1, buffer2)])
    
    return xor_result

#Always operate on raw bytes
if __name__ == '__main__':
    ### 2.
    print("#### 2. ####")
    hex_str1 = "1c0111001f010100061a024b53535009181c"
    hex_str2 = "686974207468652062756c6c277320657965"

    buffer1 = bytes.fromhex(hex_str1)
    buffer2 = bytes.fromhex(hex_str2)

    # Perform XOR operation on the byte arrays
    xor_result_bytes = xor(buffer1, buffer2)
    print(xor_result_bytes.decode('utf-8'))

    # Convert the result back to hex for display
    xor_result_hex = xor_result_bytes.hex()
    print(xor_result_hex)
    assert(xor_result_hex == '746865206b696420646f6e277420706c6179')

