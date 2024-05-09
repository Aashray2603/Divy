from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
import hashlib
import os

# Generate a random 16-byte key for AES-128
key = os.urandom(16)

# Padding functions
def pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt_message(message):
    # Hash the original message using SHA-256
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode())
    message_hash = digest.finalize()

    # Pad the message
    padded_message = pad(message.encode())

    # Encrypt the padded message using AES-128 in CBC mode
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    # Combine the hash, IV, and encrypted message
    bundle = message_hash + iv + encrypted_message

    return bundle

def decrypt_and_verify(bundle):
    # Extract the hash, IV, and encrypted message from the bundle
    message_hash = bundle[:32]
    iv = bundle[32:48]
    encrypted_message = bundle[48:]

    # Decrypt the message using AES-128 in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

    # Remove the padding from the decrypted message
    decrypted_message = unpad(padded_message)

    # Compute the hash of the decrypted message
    digest = hashes.Hash(hashes.SHA256())
    digest.update(decrypted_message)
    computed_hash = digest.finalize()

    # Verify the hash
    if computed_hash == message_hash:
        return decrypted_message.decode()
    else:
        return "Message integrity compromised!"

# Example usage
message = "Hello, Alice!"
bundle = encrypt_message(message)
print("Encrypted bundle:", bundle)

decrypted_message = decrypt_and_verify(bundle)
print("Decrypted message:", decrypted_message)


# -------- Explanation ------- #

""" The scenario you described is a typical implementation of a Message Authentication Code (MAC) system, which ensures the integrity and authenticity of the message during transmission. The combination of symmetric encryption and secure hashing algorithms like SHA-256 helps to achieve this goal.

For the encryption function, I recommend using the Advanced Encryption Standard (AES) algorithm, which is a widely used and secure symmetric encryption algorithm. AES is designed to be highly resistant to various types of attacks, and it has been extensively studied and tested by the cryptographic community.

Here's an implementation in Python using the pycryptodome library for AES encryption and the built-in hashlib module for SHA-256 hashing."""