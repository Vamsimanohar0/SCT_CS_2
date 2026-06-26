from flask import Flask, render_template, request, send_file
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PIL import Image
from io import BytesIO
import numpy as np
import hashlib

app = Flask(__name__)

# Helper to generate a fixed 16-byte key from user input
def derive_key(userkey):
    return hashlib.sha256(userkey.encode()).digest()[:16]

# Encrypt message to bytes
def encrypt_message(msg, userkey):
    key = derive_key(userkey)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(msg.encode(), AES.block_size))
    return cipher.iv + ct_bytes  # IV + ciphertext

# Decrypt bytes to message
def decrypt_message(enc_bytes, userkey):
    key = derive_key(userkey)
    iv = enc_bytes[:16]
    ct = enc_bytes[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

# Home route (optional)
@app.route('/')
def home():
    return render_template('encrypt.html')

# Render encryption form
@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        image = request.files['image']
        key = request.form['key']
        message = request.form['message']

        img = Image.open(image).convert('RGB')
        pixels = np.array(img)
        flat_pixels = pixels.flatten()

        encrypted = encrypt_message(message, key)
        enc_len = len(encrypted)

        if enc_len + 4 > len(flat_pixels):
            return "❌ Message too long for this image.", 400

        # Store encrypted data length in first 4 bytes
        flat_pixels[0] = (enc_len >> 24) & 0xFF
        flat_pixels[1] = (enc_len >> 16) & 0xFF
        flat_pixels[2] = (enc_len >> 8) & 0xFF
        flat_pixels[3] = enc_len & 0xFF

        for i in range(enc_len):
            flat_pixels[4 + i] = encrypted[i]

        new_pixels = flat_pixels.reshape(pixels.shape)
        new_img = Image.fromarray(new_pixels.astype('uint8'))

        buffer = BytesIO()
        new_img.save(buffer, format='PNG')
        buffer.seek(0)

        return send_file(buffer, as_attachment=True, download_name='encrypted.png', mimetype='image/png')

    return render_template("encrypt.html")

# Render decryption form
@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        image = request.files['image']
        key = request.form['key']

        img = Image.open(image).convert('RGB')
        flat_pixels = np.array(img).flatten()

        enc_len = (flat_pixels[0] << 24) | (flat_pixels[1] << 16) | (flat_pixels[2] << 8) | flat_pixels[3]
        encrypted_data = bytes(flat_pixels[4:4 + enc_len])

        try:
            message = decrypt_message(encrypted_data, key)
            return f"✅ Decrypted message: <strong>{message}</strong>"
        except Exception as e:
            return f"❌ Decryption failed: {str(e)}", 400

    return render_template("decrypt.html")

if __name__ == '__main__':
    app.run(debug=True)
