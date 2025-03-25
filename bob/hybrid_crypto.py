import hashlib
from Crypto.Cipher import AES, ARC4
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def derive_keys(bb84_shared_key):
    """
    Derive AES and RC4 keys from the shared BB84 key.
    """
    # Convert BB84 shared key to a string
    key_string = ''.join(map(str, bb84_shared_key))
    
    # Hash the key string using SHA-256
    hashed_key = hashlib.sha256(key_string.encode()).hexdigest()
    
    # Derive AES and RC4 keys
    aes_key = bytes.fromhex(hashed_key[:32])  # 256 bits for AES
    rc4_key = bytes.fromhex(hashed_key[32:64])  # 128 bits for RC4

    return aes_key, rc4_key

def hybrid_encrypt(data, bb84_shared_key):
    """
    Encrypt data using hybrid AES-RC4 encryption.
    """
    aes_key, rc4_key = derive_keys(bb84_shared_key)
    
    # Ensure RC4 key length is valid
    if len(rc4_key) == 0:
        raise ValueError("RC4 key length is zero bytes. Check key derivation process.")

    # Encrypt data with AES
    iv = get_random_bytes(16)  # Initialization vector for AES
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    print(type(data))
    ciphertext_aes = cipher_aes.encrypt(pad(data, AES.block_size))
    # Encrypt IV with RC4
    cipher_rc4 = ARC4.new(rc4_key)
    ciphertext_rc4 = cipher_rc4.encrypt(iv)

    # Combine AES-encrypted data and RC4-encrypted IV
    combined_encrypted_data = ciphertext_rc4 + ciphertext_aes
    return combined_encrypted_data

def hybrid_decrypt(combined_encrypted_data, bb84_shared_key):
    """
    Decrypt data using hybrid AES-RC4 decryption.
    """
    aes_key, rc4_key = derive_keys(bb84_shared_key)

    iv_length = 16  # IV for AES-CBC is typically 16 bytes
    encrypted_iv = combined_encrypted_data[:iv_length]
    encrypted_data = combined_encrypted_data[iv_length:]

    # Decrypt the IV with RC4
    decipher_rc4 = ARC4.new(rc4_key)
    decrypted_iv = decipher_rc4.decrypt(encrypted_iv)

    # Decrypt the AES-encrypted data using the decrypted IV
    decipher_aes = AES.new(aes_key, AES.MODE_CBC, decrypted_iv)
    decrypted_data = unpad(decipher_aes.decrypt(encrypted_data), AES.block_size)

    return decrypted_data

# For testing as a script
if __name__ == "__main__":
    # Example input
    bb84_shared_key = [1, 0, 1, 1, 0, 1, 0, 1, 1, 0]  # Replace with actual BB84 output
    data = input("Enter data to encrypt: ").encode()

    print("\nEncrypting data...")
    encrypted_data = hybrid_encrypt(data, bb84_shared_key)
    print("Encrypted Data:", encrypted_data)

    print("\nDecrypting data...")
    decrypted_data = hybrid_decrypt(encrypted_data, bb84_shared_key)
    print("Decrypted Data:", decrypted_data.decode())
