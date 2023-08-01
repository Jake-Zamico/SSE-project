from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256
import time
import json

def generate_key(password, salt):
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    return key

def encrypt_data(key, data):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return iv + ciphertext

def decrypt_data(key, encrypted_data):
    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data.decode()

def search_data(key, encrypted_data_list, keyword):
    results = []
    for encrypted_data in encrypted_data_list:
        decrypted_data = decrypt_data(key, encrypted_data)
        if keyword in decrypted_data:
            results.append(decrypted_data)
    return results

if __name__ == "__main__":
    s_time = time.time()
    password = "your_password"  # Replace with your password
    salt = get_random_bytes(16)

    # Read data from a JSON file
    json_file = "data.json"  # Replace with your JSON file path
    with open(json_file, "r") as file:
        data_list = json.load(file)

    key = generate_key(password.encode(), salt)

    encrypted_data_list = [encrypt_data(key, data) for data in data_list]

    keyword = input("Enter a keyword to search for: ")
    search_results = search_data(key, encrypted_data_list, keyword)
    e_time = time.time()
    if search_results:
        print(f"Matching Results: {len(search_results)}")
        print(f"time: {e_time - s_time}")
    else:
        print("No matching results found.")
