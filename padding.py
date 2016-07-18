import os
import binascii
import random
import sys

def pad_pkcs7(x):
    ''' Pad the byte array according to the PKCS7 standard.
    If the length is 15, pad with 0x1 = 16 - 15
    If the length is 14, pad with 0x2 = 16 - 14
    ...
    '''
    length = len(x)
    delta = 16 - length
    result = x[:]
    for i in range(length, 16):
        result.append(delta)
    assert len(result) == 16
    return result

def is_valid_pad_pkcs7(x):
    ''' Check that the byte array has a valid padding.
    The padding value must be a value between 1 and 16.
    '''
    pad_value = x[-1]
    if pad_value == 0:
        return False
    for i in range(len(x) - 1, len(x) - pad_value - 1, -1):
        if x[i] != pad_value:
            return False
    return True

def xor(x, y):
    ''' XOR two lists of bytes.
    '''
    return map(lambda (xx, yy) : xx ^ yy, zip(x, y))

def random_vector(n):
    ''' Generate a random byte list with n elements.
    '''
    return [random.randint(0, 255) for i in range(n)]

def encrypt_cbc(key, iv, vectors):
    ''' "Encrypt" a list of plaintext blocks using the given key and IV in CBC mode.
    We don't really encrypt here... we just XOR the plaintext with the key. This has
    no impact on the PO attack.
    '''

    # Pad, if necessary
    if len(vectors[-1]) < 16:
        vectors[-1] = pad_pkcs7(vectors[-1])
    else:
        vectors.append(pad_pkcs7([]))

    result = []
    state = iv
    for i, v in enumerate(vectors):
        input_block = xor(state, v)
        state = xor(key, input_block) # replacement for AES
        result.append(state)
    return result

def decrypt_cbc(key, iv, vectors):
    ''' Invert our "encryption" in CBC mode.
    '''
    pt = []
    state = iv
    for i, v in enumerate(vectors):
        next_state = v
        output_block = xor(key, v) # replacement for AESi
        xor_result = xor(state, output_block)
        pt.append(xor_result)
        state = next_state

    if not is_valid_pad_pkcs7(pt[-1]):
        raise Exception("Invalid padding")
    return pt

def break_last_block(ct, decrypt_oracle):
    ''' Use the padding decryption oracle to recover the plaintext bytes
    in the last block of ciphertext.
    '''
    block = [0 for i in range(16)]
    
    plaintext = []
    pad_vector = [0] * 16

    # Start from the last byte and work towards the first.
    # We'll iterate 16 * 256 = 4096 times in the worst case.
    for guess_index in range(15, -1, -1):
        pad = 16 - guess_index
        
        # Create the fake padding vector based on the guess index.
        # This vector contains the desired padding value at the guess_index
        # and beyond, and zeroes in all preceding entries.
        for i in range(guess_index, 16):
            pad_vector[i] ^= pad

        # Try each byte
        found = False
        for g in range(0, 256):
            if g == pad:
                continue

            # Apply the padding guess to the first-to-last ciphertext block.
            # This will affect the last ciphertext block during decryption.
            # Also, save the guess plaintext byte in the padding vector. 
            pad_vector[guess_index] ^= g
            ct[-2] = xor(ct[-2], pad_vector)
            
            # Try to decrypt the ciphertext. If it passes, we guessed correctly.
            try:
                pt = decrypt_oracle(ct)

                # Since we guessed right, revert back to the original first-to-last
                # ciphertext block and save the guessed plaintext. 
                ct[-2] = xor(ct[-2], pad_vector)

                # Save the plaintext byte in our block
                block[guess_index] = g
                found = True
                break
            except: # padding failed, so retry
                pass

            # We failed, so revert the first-to-last ciphertext block and remove the 
            # byte guess for the next round
            ct[-2] = xor(ct[-2], pad_vector)
            pad_vector[guess_index] ^= g

        # If it wasn't found then it must be the pad (since we skipped it above)
        if not found:
            block[guess_index] = pad
            pad_vector[guess_index] ^= pad
        
        # Remove the padding guess from the vector
        # At the end of this step, this will contain the correctly
        # guessed plaintext bytes in the final slots in the vector. This is necessary
        # since, in the next iteration, we rely on knowledge of those bytes to XOR 
        # them out and decrypt to the desired padding value
        for i in range(guess_index, 16):
            pad_vector[i] ^= pad
    return block

def padding_oracle(ct, decrypt_oracle):
    ''' Encrypt each ciphertext block (except the first, since we don't have the IV).
    '''
    pt = []
    for block_index in range(len(ct) - 1, 0, -1): # need the IV to break the first block
        pt.insert(0, break_last_block(ct[0:block_index + 1], decrypt_oracle))
    return pt

def main(args):
    N = int(args[0])

    # Generate the key, IV, and plaintext (randomly)
    key = random_vector(16)
    iv = random_vector(16)
    plaintext = [random_vector(16) for i in range(N - 1)]


    # Encrypt with CBC
    ct = encrypt_cbc(key, iv, plaintext)

    # Build the oracle 
    oracle = lambda v: decrypt_cbc(key, iv, v)

    # Run the oracle attack
    recovered_plaintext = padding_oracle(ct, oracle)

    # Verify that the attack worked.
    for i in range(1, N - 1):
        print recovered_plaintext[i - 1]
        print plaintext[i]
        assert recovered_plaintext[i - 1] == plaintext[i]

if __name__ == "__main__":
    main(sys.argv[1:])
