import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from PIL import Image
import os
import hashlib
import base64
from io import BytesIO

# Function to generate a valid AES key from the password
def generate_key(password):
    # Use SHA256 to hash the password and return a 32-byte key
    return hashlib.sha256(password.encode('utf-8')).digest()

# Function to encrypt the image
def encrypt_image():
    try:
        # Get the image file path
        file_path = filedialog.askopenfilename(title="Select an Image", filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.bmp")])
        if not file_path:
            return

        # Get the password from the entry widget
        password = password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return

        # Read the image
        with open(file_path, "rb") as img_file:
            image_data = img_file.read()

        # Generate a valid key and IV from the password
        key = generate_key(password)  # Generate 32-byte key using SHA-256
        iv = os.urandom(16)  # Generate a random 16-byte IV

        # Padding the image data to make it a multiple of 128 bits
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(image_data) + padder.finalize()

        # Encrypt the data
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Save the encrypted image
        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, "wb") as enc_file:
            enc_file.write(iv + encrypted_data)  # Save IV with encrypted data

        messagebox.showinfo("Success", f"Image encrypted successfully!\nSaved as: {encrypted_file_path}")

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during encryption: {str(e)}")


# Function to decrypt the image
def decrypt_image():
    try:
        # Get the encrypted image file path
        enc_file_path = filedialog.askopenfilename(title="Select an Encrypted Image", filetypes=[("Encrypted files", "*.enc")])
        if not enc_file_path:
            return

        # Get the password from the entry widget
        password = password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return

        # Read the encrypted image
        with open(enc_file_path, "rb") as enc_file:
            enc_data = enc_file.read()

        # Extract the IV and encrypted data
        iv = enc_data[:16]  # First 16 bytes are the IV
        encrypted_data = enc_data[16:]

        # Generate the key from the password
        key = generate_key(password)  # Generate 32-byte key using SHA-256

        # Decrypt the data
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        image_data = unpadder.update(decrypted_data) + unpadder.finalize()

        # Save the decrypted image
        decrypted_file_path = enc_file_path.replace(".enc", "_decrypted.png")
        with open(decrypted_file_path, "wb") as dec_file:
            dec_file.write(image_data)

        messagebox.showinfo("Success", f"Image decrypted successfully!\nSaved as: {decrypted_file_path}")

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during decryption: {str(e)}")


# Setup GUI using tkinter
root = tk.Tk()
root.title("Image Encrypter/Decrypter")

# Set window size
root.geometry("400x250")

# Password label and entry widget
password_label = tk.Label(root, text="Enter Password:")
password_label.pack(pady=10)

password_entry = tk.Entry(root, show="*", width=40)
password_entry.pack(pady=5)

# Buttons to trigger encryption and decryption
encrypt_button = tk.Button(root, text="Encrypt Image", command=encrypt_image, width=20)
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(root, text="Decrypt Image", command=decrypt_image, width=20)
decrypt_button.pack(pady=10)

# Run the tkinter loop
root.mainloop()
