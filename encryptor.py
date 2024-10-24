from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import requests
import time
import binascii

key = binascii.unhexlify("DFC170B2F484BB16CEA0EE8FFF53E21F")  # Convert hex to bytes
iv = binascii.unhexlify("7F2C02DE7B7EF2E879A12798232C21A6")    # Convert hex to bytes

def send_data(data):
    while True:
        # Simulate sending some data
        response = requests.post('http://127.0.0.1:5000/upload', data=data)
        print("sent")
        time.sleep(2)  # Wait for 2 seconds before sending the next message


def encrypt_message(plaintext, key, iv):
    # Convert key to bytes and make sure it's 16 bytes (AES-128 requires a 16-byte key)

    # Padding the plaintext to be a multiple of 16 bytes
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

    # AES-128 encryption in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Return the IV and ciphertext, as the IV is needed for decryption
    return iv + ciphertext


if __name__ == "__main__":
    secret_message = "Hello World!"
    send_data(encrypt_message(secret_message, key, iv))