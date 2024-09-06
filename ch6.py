from utils.ch2 import xor
from ch3 import single_byte_xor_cipher
from utils.score import score_text
from typing import List, Tuple
from utils.base64_to_byte import base64_to_byte

#The Hamming distance is just the number of differing bits
def hamming_distance(str1: bytes, str2: bytes) -> int:
    if len(str1) != len(str2):
        raise ValueError("Strings must be of equal length.")
    
    # XOR the bytes of the strings
    xor_result = xor(str1, str2)
    
    # count the set bits in the result
    distance = sum(bin(byte).count('1') for byte in xor_result)
    return distance

# calculates the Hamming distance between multiple pairs of blocks for each key size, averages these distances,
# and then uses the average to rank the key sizes.
def possible_key_sizes(data: bytes) -> List[Tuple[float, int]]:
    keysize_scores = [] # avg. hamming distance for each keysize
        
    for keysize in range(2, 41): 
        distances = [] 
        num_samples = (len(data) // keysize) 
        for i in range(num_samples):
            # Calculate start indices for the blocks
            start1 = i * keysize
            start2 = start1 + keysize
            # Ensure we do not go out of bounds
            if start2 + keysize > len(data):
                break
            block1 = data[start1:start2]
            block2 = data[start2:start2 + keysize]
            # Calculate and store the normalized Hamming distance for these pairs of data
            distances.append(hamming_distance(block1, block2) / keysize)
        
        # Find the avgerage hamming distance for the keysize
        if distances:
            avg_distance = sum(distances) / len(distances)
            keysize_scores.append((avg_distance, keysize))
    
    if not keysize_scores:
        raise ValueError("The data length is too short relative to the key sizes")
    
    # Shorter hamming dist is better, fewer differeing bits
    sorted_keysizes = sorted(keysize_scores, key=lambda tup: tup[0])
    return sorted_keysizes
    
def key_for_keysize(data:bytes, probable_keysizes: List[Tuple[float, int]]) -> List[str]:
    possible_keys = [] # Most probable key for each key size
    for guessed_key_size in probable_keysizes:
        # for each byte position in keysize, slice with the step of keysize
        # Gathers all bytes that would be XORed with the same byte of the key if the key were applied in a repeating fashion
        
        # starting from index i and then picking every guessed_key_size[1]th element thereafter
        # data-bytes encrypted with same key-byte are in the same column
        transposed_blocks = [data[i::guessed_key_size[1]] for i in range(guessed_key_size[1])] 
        
        full_key = []
        # Try to determine each key-byte
        for block in transposed_blocks:
            _, block_key = single_byte_xor_cipher(block)
            full_key.append(chr(block_key))
            
        final_key = ''.join(full_key)
        possible_keys.append(final_key)
        
    return possible_keys


def find_correct_repeating_xor_key(data: bytes, possible_keys: List[str]) -> Tuple[str, bytes]:
    best_score = 0
    final_decrypted_text = None
    best_key = None
    
    for possible_key in possible_keys:
        repeated_key = (possible_key * (len(data) // len(possible_key) + 1))[:len(data)]
        decrypted_data = xor(data, repeated_key.encode())
        current_score = score_text(decrypted_data)
        
        # Update if current is better
        if best_score < current_score:
            best_score = current_score
            final_decrypted_text = decrypted_data
            best_key = possible_key
    
    return  best_key, final_decrypted_text



#Always operate on raw bytes
if __name__ == '__main__':
    ### 6.
    print("\n#### 6. ####")
    str1 = "this is a test"
    str2 = "wokka wokka!!!"
    buffer1 = str.encode(str1)
    buffer2 = str.encode(str2)
    dist = hamming_distance(buffer1, buffer2)
    assert(dist == 37)
    print("Hamming distance test:", dist)
    
    # Read and decode the file from base64
    with open("texts/6.txt", 'r') as file:
        encoded_data = file.read()
    encoded_data = encoded_data.replace('\n', '')
    data = base64_to_byte(encoded_data) # bytes
    
    # Find possible key sizes, i.e. those with smallest hamming distance
    sorted_keysizes = possible_key_sizes(data)
    
    # For each possible key_size: Use single_byte_xor to find each key byte in the possible key 
    possible_keys = key_for_keysize(data, sorted_keysizes[:len(sorted_keysizes)//2])
    
    # Score the decrypted text for each key, and see which yields the highest score
    key, decrypted_message = find_correct_repeating_xor_key(data, possible_keys)
    print("Key for 6.txt : ", key, '\n')

    with open("6decoded.txt", 'w') as file:
        file.write(decrypted_message.decode("utf-8"))
      