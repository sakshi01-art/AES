from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256


def derive_key(password, salt):
    return PBKDF2(
        password.encode("utf-8"),
        salt,
        dkLen=32,              # AES-256 = 32 bytes
        count=200000,
        hmac_hash_module=SHA256
    )


def encrypt_file(input_file, output_file, password):
    salt = get_random_bytes(16)
    key = derive_key(password, salt)

    cipher = AES.new(key, AES.MODE_GCM)

    with open(input_file, "rb") as file:
        data = file.read()

    ciphertext, tag = cipher.encrypt_and_digest(data)

    with open(output_file, "wb") as file:
        file.write(salt)
        file.write(len(cipher.nonce).to_bytes(2, "big"))
        file.write(cipher.nonce)
        file.write(len(tag).to_bytes(2, "big"))
        file.write(tag)
        file.write(ciphertext)

    print("File encrypted successfully!")


def decrypt_file(input_file, output_file, password):
    try:
        with open(input_file, "rb") as file:
            salt = file.read(16)

            nonce_length = int.from_bytes(file.read(2), "big")
            nonce = file.read(nonce_length)

            tag_length = int.from_bytes(file.read(2), "big")
            tag = file.read(tag_length)

            ciphertext = file.read()

        key = derive_key(password, salt)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        data = cipher.decrypt_and_verify(ciphertext, tag)

        with open(output_file, "wb") as file:
            file.write(data)

        print("File decrypted successfully!")

    except ValueError:
        print("Wrong password or corrupted encrypted file!")

    except FileNotFoundError:
        print("File not found. Check the file name/path.")


# Password
password = "MySecurePassword123"

encrypt_file("test.txt", "encrypted.aes", password)
decrypt_file("encrypted.aes", "decrypted.txt", password)