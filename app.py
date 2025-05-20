from flask import Flask, render_template_string, request
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os, base64

app = Flask(__name__)

KEY = os.urandom(32)  # AES-256 key (32 bytes)
IV_LENGTH = 16

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Text Encryption</title>
</head>
<body>
    <h2>Text Encryption App</h2>
    <form method="post">
        <textarea name="text" rows="4" cols="50" placeholder="Enter text here...">{{ text }}</textarea><br>
        <input type="submit" name="action" value="Encrypt">
        <input type="submit" name="action" value="Decrypt">
    </form>
    <p><strong>Result:</strong> {{ result }}</p>
</body>
</html>
"""

def encrypt(text):
    iv = os.urandom(IV_LENGTH)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ct).decode()

def decrypt(encoded):
    data = base64.b64decode(encoded.encode())
    iv, ct = data[:IV_LENGTH], data[IV_LENGTH:]
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_text = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_text) + unpadder.finalize()

@app.route('/', methods=['GET', 'POST'])
def index():
    result, text = '', ''
    if request.method == 'POST':
        text = request.form['text']
        action = request.form['action']
        try:
            if action == 'Encrypt':
                result = encrypt(text)
            elif action == 'Decrypt':
                result = decrypt(text).decode()
        except Exception as e:
            result = f"Error: {e}"
    return render_template_string(HTML_TEMPLATE, result=result, text=text)

if __name__ == '__main__':
    app.run(debug=True)



