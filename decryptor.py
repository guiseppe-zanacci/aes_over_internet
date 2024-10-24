from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from flask import Flask, request, jsonify

key = "DFC170B2F484BB16CEA0EE8FFF53E21F"
iv = "7F2C02DE7B7EF2E879A12798232C21A6"

def decrypt_message(encrypted_text, key, iv):
    # Convert key to bytes and make sure it's 16 bytes (AES-128 requires a 16-byte key)

    # AES-128 decryption in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_padded_message = decryptor.update(encrypted_text) + decryptor.finalize()

    # Unpad the decrypted message
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted_padded_message) + unpadder.finalize()

    return plaintext


app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload():
    data = request.data.decode()  # Decode incoming data
    print("Received data from client")
    print(decrypt_message(data, key, iv))
    return



if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000)  # Listen on localhost at port 5000


