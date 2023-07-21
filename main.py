from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

def generate_AES_key():
    return get_random_bytes(32)

def AES_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce, ciphertext, tag

def AES_decrypt(key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data

def generate_RSA_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def RSA_encrypt(public_key, data):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(data)
    return ciphertext

def RSA_decrypt(private_key, ciphertext):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    data = cipher.decrypt(ciphertext)
    return data

def main():
    print("Choose encryption algorithm:")
    print("1. AES")
    print("2. RSA")
    choice = int(input("Enter 1 or 2: "))

    if choice == 1:
        aes_key = generate_AES_key()
        data_to_encrypt = input("Enter the text to encrypt with AES: ").encode('utf-8')

        nonce, ciphertext, tag = AES_encrypt(aes_key, data_to_encrypt)
        print("AES Encrypted:", ciphertext)

        decrypted_data = AES_decrypt(aes_key, nonce, ciphertext, tag)
        print("AES Decrypted:", decrypted_data.decode('utf-8'))

    elif choice == 2:
        private_key, public_key = generate_RSA_key_pair()
        data_to_encrypt_rsa = input("Enter the text to encrypt with RSA: ").encode('utf-8')

        encrypted_rsa_data = RSA_encrypt(public_key, data_to_encrypt_rsa)
        print("RSA Encrypted:", encrypted_rsa_data)

        decrypted_rsa_data = RSA_decrypt(private_key, encrypted_rsa_data)
        print("RSA Decrypted:", decrypted_rsa_data.decode('utf-8'))

    else:
        print("Invalid choice. Please enter 1 or 2.")

if __name__ == "__main__":
    main()
