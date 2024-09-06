from Crypto.Cipher import AES
from utils.ch9 import pad, unpad
from utils.ch2 import xor 

class AESCipher:
    def __init__(self, key: bytes):
        self.key = key
        self.block_size = AES.block_size  # AES block size (16 bytes)
        
###########################################################################################################
    def _aes_ecb_encrypt(self, data: bytes) -> bytes:
        """Encrypt data using AES in ECB mode."""
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(data)

    def _aes_ecb_decrypt(self, data: bytes) -> bytes:
        """Decrypt data using AES in ECB mode."""
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.decrypt(data)
    
###########################################################################################################

    def _encrypt_cbc(self, plaintext: bytes, iv: bytes) -> bytes:
        """Encrypt plaintext using CBC mode manually with ECB as the core operation.""" 
        padded_text = pad(plaintext, self.block_size)
        if len(padded_text) % self.block_size != 0:
            raise ValueError("Padding failed")
        
        blocks = [padded_text[i:i+self.block_size] for i in range(0, len(padded_text), self.block_size)]
        ciphertext = b""
        
        xored_block = xor(blocks[0], iv)
        ciphertext += self._aes_ecb_encrypt(xored_block)
        
        for block in blocks[1:]:
            xored_block = xor(block, ciphertext[-self.block_size:])
            encrypted_block = self._aes_ecb_encrypt(xored_block)
            ciphertext += encrypted_block
        return ciphertext

    def _decrypt_cbc(self, ciphertext: bytes, iv: bytes) -> bytes:
        """Decrypt ciphertext using CBC mode manually with ECB as the core operation."""
        
        blocks = [ciphertext[i:i+self.block_size] for i in range(0, len(ciphertext), self.block_size)]
        decrypted_text = b""
        
        prev_block = iv
        for block in blocks:
            decrypted_block = self._aes_ecb_decrypt(block)
            # XOR the decrypted block with the previous ciphertext block (IV for the first block)
            xored_block = xor(decrypted_block, prev_block)
            decrypted_text += xored_block
            # Update the previous block to the current ciphertext block for next iteration
            prev_block = block
            
        return unpad(decrypted_text, self.block_size)
    
###########################################################################################################

    def encrypt(self, plaintext: bytes, mode: str, iv: bytes = None) -> bytes:
        """Encrypt data in specified mode with optional IV for CBC."""  
        if not(isinstance(self.key, bytes) and len(self.key) == 16):
            raise ValueError("Key must be 16 bytes")
        if not isinstance(plaintext, bytes):
            raise ValueError("Plaintext must be in bytes")
        
        if mode.upper() == "ECB":
            ciphertext = b''
            padded_text = pad(plaintext, self.block_size)
            if len(padded_text) % self.block_size != 0:
                raise ValueError("Padding failed")
            
            blocks = [padded_text[i:i+self.block_size] for i in range(0, len(padded_text), self.block_size)]
            for block in blocks:
                ciphertext += self._aes_ecb_encrypt(block)
            return ciphertext
        
        elif mode.upper() == "CBC":
            if iv is None:
                raise ValueError("IV must be provided for CBC mode.")
            if not(isinstance(iv, bytes) and len(iv) == 16):
                raise ValueError("IV must be 16 bytes")
    
            return self._encrypt_cbc(plaintext, iv)
        else:
            raise ValueError("Invalid AES mode")


    def decrypt(self, ciphertext: bytes, mode: str, iv: bytes = None) -> bytes:
        """Decrypt data in specified mode with optional IV for CBC."""
        if not(isinstance(self.key, bytes) and len(self.key) == 16):
            raise ValueError("Key must be 16 bytes")
        if not isinstance(ciphertext, bytes):
            raise ValueError("Ciphertext must be bytes")
        if len(ciphertext) % self.block_size != 0:
                raise ValueError("Ciphertext must be a multiple of the block size")
        
        plaintext = b''
        if mode.upper() == "ECB":        
            blocks = [ciphertext[i:i+self.block_size] for i in range(0, len(ciphertext), self.block_size)]
            for block in blocks:
                plaintext += self._aes_ecb_decrypt(block)
            return unpad(plaintext, self.block_size)
        
        
        elif mode.upper() == "CBC":
            if iv is None:
                raise ValueError("IV must be provided for CBC mode.")
            if not(isinstance(iv, bytes) and len(iv) == 16):
                raise ValueError("IV must be 16 bytes")
            return self._decrypt_cbc(ciphertext, iv)
        
        else:
            raise ValueError("Unsupported mode.")

