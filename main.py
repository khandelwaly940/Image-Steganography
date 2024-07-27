import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter import ttk
from PIL import Image
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os

# Convert encoding data into 8-bit binary form using ASCII value of characters
def genData(data):
    newd = [format(ord(i), '08b') for i in data]
    return newd

# Pixels are modified according to the 8-bit binary data and finally returned
def modPix(pix, data):
    datalist = genData(data)
    lendata = len(datalist)
    imdata = iter(pix)

    for i in range(lendata):
        pix = [value for value in next(imdata)[:3] +
               next(imdata)[:3] +
               next(imdata)[:3]]

        for j in range(8):
            if datalist[i][j] == '0' and pix[j] % 2 != 0:
                pix[j] -= 1
            elif datalist[i][j] == '1' and pix[j] % 2 == 0:
                pix[j] = pix[j] - 1 if pix[j] != 0 else pix[j] + 1

        if i == lendata - 1:
            if pix[-1] % 2 == 0:
                pix[-1] = pix[-1] - 1 if pix[-1] != 0 else pix[-1] + 1
        else:
            if pix[-1] % 2 != 0:
                pix[-1] -= 1

        pix = tuple(pix)
        yield pix[0:3]
        yield pix[3:6]
        yield pix[6:9]

def encode_enc(newimg, data):
    w = newimg.size[0]
    (x, y) = (0, 0)

    for pixel in modPix(newimg.getdata(), data):
        newimg.putpixel((x, y), pixel)
        if x == w - 1:
            x = 0
            y += 1
        else:
            x += 1

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# Encode data into image
def encode(image_path, data, output_path, password):
    image = Image.open(image_path, 'r')
    if len(data) == 0:
        raise ValueError('Data is empty')

    # Generate a random salt
    salt = os.urandom(16)
    key = derive_key(password, salt)
    cipher = Fernet(key)

    # Encrypt the data
    encrypted_data = cipher.encrypt(data.encode())
    
    # Convert salt to a string and prepend it to the encrypted data
    encrypted_data_with_salt = base64.urlsafe_b64encode(salt) + b' ' + encrypted_data

    newimg = image.copy()
    encode_enc(newimg, encrypted_data_with_salt.decode())
    newimg.save(output_path, str(output_path.split(".")[1].upper()))
    messagebox.showinfo("Success", "Data encoded and saved to new image!")

# Decode the data in the image
def decode(image_path, password):
    image = Image.open(image_path, 'r')
    data = ''
    imgdata = iter(image.getdata())

    while True:
        pixels = [value for value in next(imgdata)[:3] +
                  next(imgdata)[:3] +
                  next(imgdata)[:3]]

        binstr = ''.join(['0' if i % 2 == 0 else '1' for i in pixels[:8]])

        data += chr(int(binstr, 2))
        if pixels[-1] % 2 != 0:
            break

    # Split the salt and the encrypted data
    salt, encrypted_data = data.split(' ', 1)
    salt = base64.urlsafe_b64decode(salt)
    
    # Derive the key
    key = derive_key(password, salt)
    cipher = Fernet(key)
    
    # Decrypt the data
    try:
        decrypted_data = cipher.decrypt(encrypted_data.encode())
        messagebox.showinfo("Decoded Data", decrypted_data.decode())
    except Exception as e:
        messagebox.showerror("Error", "Failed to decrypt data. Check your password.")

# Main GUI
class SteganographyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Image Steganography")
        self.geometry("350x250")
        self.configure(bg="#2c3e50")

        self.style = ttk.Style(self)
        self.style.configure("TButton", font=("Helvetica", 14), padding=10)
        self.style.configure("TLabel", font=("Helvetica", 14), padding=10, background="#2c3e50", foreground="#ecf0f1")

        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Image Steganography", font=("Helvetica", 24, "bold"), bg="#2c3e50", fg="#ecf0f1").pack(pady=20)

        ttk.Button(self, text="Encode Data", command=self.encode_data, style="TButton").pack(pady=10)
        ttk.Button(self, text="Decode Data", command=self.decode_data, style="TButton").pack(pady=10)

    def encode_data(self):
        image_path = filedialog.askopenfilename(title="Select Image", filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
        if not image_path:
            return

        data = simpledialog.askstring("Enter Data", "Enter the data to encode:")
        if not data:
            return

        password = simpledialog.askstring("Enter Password", "Enter a password to encrypt the data:", show='*')
        if not password:
            return

        output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
        if not output_path:
            return

        encode(image_path, data, output_path, password)

    def decode_data(self):
        image_path = filedialog.askopenfilename(title="Select Image", filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
        if not image_path:
            return

        password = simpledialog.askstring("Enter Password", "Enter the password to decrypt the data:", show='*')
        if not password:
            return

        decode(image_path, password)

if __name__ == "__main__":
    app = SteganographyApp()
    app.mainloop()
