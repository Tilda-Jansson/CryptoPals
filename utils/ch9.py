def pad(data: bytes, block_size: int) -> bytes:
    # if the data length is a multiple of the block_size we add a whole new block of padding
    # (otherwise it would be difficult when removing the padding to guess the padding length)
    
    padding_bytes = block_size - (len(data) % block_size) # number of padding bytes
    
    padding = bytes([padding_bytes]) * padding_bytes
    return data + padding
    
def unpad(data: bytes, block_size: int) -> bytes:
    length = len(data)
    if length % block_size != 0 or length == 0:
        raise ValueError("Input data is not padded, or empty")
    
    padded_value = data[-1] # number of padded bytes
    
    # Check if the padded value is within the valid range
    if padded_value > block_size or padded_value < 1:
        raise ValueError("Padding is invalid")
    
    # Check if the padded bytes have correct value
    if data[-padded_value:] != bytes([padded_value]) * padded_value:
        raise ValueError("Padding is invalid")
    
    return data[:-padded_value]




#Always operate on raw bytes
if __name__ == '__main__':
    str1 = b"YELLOW SUBMARINE"
    padded = pad(str1, 20)
    print(padded)
    unpadded = unpad(padded, 20)
    print(unpadded)