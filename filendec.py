#Here is a pyhton script for file encryption and decryption using the cryptography library
from cryptography.fernet import Fernet

# generate a key (run once and save)
def generate_key():
	 key = Fernet.generate_key()
	 with open("secret.key", "wb") as key_file:
	 	key_file.write(key)

# load the saved key
def load_key():
	return open("secret.key", "rb").read()
#encrypt a file
def encrypt_file(filename, key):
	f = Fernet(key)
	with open(filename, "rb") as file:
		data = file.read()
	encrypted = f.encrypt(data)
	with open(filename + ".enc", "wb") as file:
		file.write(encrypted)
#decryption of file
def Decrypt_file(filename, key):
	f = Fernet(key)
	with open(filename, "rb") as file:
		encrypted_data = file.read()
	decrypted = f.decrypt(encrypted_data)
	with open("decrypted_" + filename.replace(".enc", " "), "wb")  as file:
		file.write(decrypted)
#generate_key()
key = load_key()
#encrypt_file("secret.txt", key)
Decrypt_file("secret.txt.enc", key)
