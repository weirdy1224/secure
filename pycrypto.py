from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
def generate_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password, salt, dkLen=32)
def encrypt(data: str, password: str) -> str:
    salt = get_random_bytes(16)
    key = generate_key(password, salt)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pad_len = AES.block_size - len(data) % AES.block_size
    padded_data = data + chr(pad_len) * pad_len
    encrypted_data = cipher.encrypt(padded_data.encode('utf-8'))
    return base64.b64encode(salt + iv + encrypted_data).decode('utf-8')
def decrypt(encrypted_data: str, password: str) -> str:
    decoded_data = base64.b64decode(encrypted_data)
    salt = decoded_data[:16]
    iv = decoded_data[16:32]
    ciphertext = decoded_data[32:]
    key = generate_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded_data = cipher.decrypt(ciphertext)
    pad_len = decrypted_padded_data[-1]
    return decrypted_padded_data[:-pad_len].decode('utf-8')
password = "securepassword123"
data = "Sensitive information to encrypt"
encrypted_text = encrypt(data, password)
print("Encrypted:", encrypted_text)
decrypted_text = decrypt(encrypted_text, password)
print("Decrypted:", decrypted_text)
