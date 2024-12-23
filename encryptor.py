from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import requests
import time
import binascii

import config

def send_data(data):
    count = 1
    while True:
        # Simulate sending some data
        try:
            response = requests.post(f'http://{config.server_ip}:{config.upload_port}/{config.upload_endpoint}', data=data)
            print("Successfully sent " + str(count))
        except:
            print("Error connecting " + str(count))
        count += 1
        time.sleep(2)  # Wait for 2 seconds before sending the next message


def encrypt_message(plaintext, key, iv):

    padder = padding.PKCS7(128).padder() # PKCS7 padder
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize() # Encodes to utf-8, returns bytes

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())  # AES-128 CBC mode
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Return the IV and ciphertext, as the IV is needed for decryption
    return ciphertext


if __name__ == "__main__":
    key = binascii.unhexlify(config.key)
    iv = binascii.unhexlify(config.iv)
    secret_message = "Hello World!"
    send_data(encrypt_message(secret_message, key, iv))