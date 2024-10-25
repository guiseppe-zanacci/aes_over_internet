from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from flask import Flask, request
import binascii

import config


def decrypt_message(encrypted_text, key, iv):
    # AES-128 decryption in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    encrypted_text = encrypted_text.decode('utf-8')

    # Decrypt the ciphertext
    decrypted_padded_message = decryptor.update(encrypted_text) + decryptor.finalize()

    # Unpad the decrypted message
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted_padded_message) + unpadder.finalize()

    return plaintext.decode('utf-8')  # Convert bytes back to string

app = Flask(__name__)

@app.route(f'/{config.upload_endpoint}', methods=['POST'])
def upload():
    data = request.data  # Get raw binary data
    print("Received data from client")
    decrypted_message = decrypt_message(data, key, iv)
    print(f"Decrypted Message: {decrypted_message}")
    return 'Data received', 200

if __name__ == "__main__":
    key = binascii.unhexlify(config.key)
    iv = binascii.unhexlify(config.iv)
    app.run(host=config.server_ip, port=config.upload_port)  # Listen on localhost at port 5000
