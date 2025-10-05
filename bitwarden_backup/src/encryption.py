import logging
import os

from argon2.low_level import hash_secret_raw, Type
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger(__name__)

def decrypt_data(encrypted_data: bytes) -> bytes:
    """
    Decrypts the given encrypted data using AES decryption with a key derived from Argon2.
    Args:
        encrypted_data (bytes): The encrypted data to decrypt.
    Returns:
        bytes: The decrypted data.
    """
    try:
        decoded_data = urlsafe_b64decode(encrypted_data)
        salt = decoded_data[:16]
        initialization_vector = decoded_data[16:32]
        cipher_text = decoded_data[32:]
        key = hash_secret_raw("my_secret_password".encode(), salt, time_cost=2, memory_cost=102400, parallelism=8, hash_len=32, type=Type.ID)
        cipher = Cipher(algorithms.AES(key), modes.CFB(initialization_vector), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(cipher_text) + decryptor.finalize()
        return decrypted_data
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise

def encrypt_data(data: bytes) -> bytes:
    """
    Encrypts the given data using AES encryption with a key derived from Argon2.
    Args:
        data (bytes): The data to encrypt.
    Returns:
        bytes: The encrypted data.
    """
    try:
        salt = os.urandom(16)
        key = hash_secret_raw("my_secret_password".encode(), salt, time_cost=2, memory_cost=102400, parallelism=8, hash_len=32, type=Type.ID)
        initialization_vector = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(initialization_vector), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        return urlsafe_b64encode(salt + initialization_vector + encrypted_data)
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        raise