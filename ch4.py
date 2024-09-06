from ch3 import single_byte_xor_cipher
from utils.score import score_text

# Finds line that has been encrypted by single-character XOR
def detect_single_character_xor(file):
    best_score_overall = 0
    best_text_overall = None
    best_key_overall = None
    line_number = 0
    best_line_number = 0

    with open(file, 'r') as file:
        for line in file:
            line = line.strip()  # Remove newline characters
            data = bytes.fromhex(line)
            
            decrypted_text, key = single_byte_xor_cipher(data) # tries all possible keys and returns the best one based on the score
            current_score = score_text(decrypted_text) # just to get the score for the line with the possible key
            
            if current_score > best_score_overall:
                best_score_overall = current_score
                best_text_overall = decrypted_text
                best_key_overall = key
                best_line_number = line_number
            
            line_number += 1

    print("Best line:", best_line_number)
    print("Key:", chr(best_key_overall))
    print("Decrypted text:", best_text_overall.decode('ascii'))
    
#Always operate on raw bytes
if __name__ == '__main__':
    print("#### 4. ####")
    detect_single_character_xor("texts/4.txt")