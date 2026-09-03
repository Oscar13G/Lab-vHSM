from hsm.connection import open_session
from hsm.aes import encrypt_aes, decrypt_aes


def main():

    plaintext = b"Hola mundo para el HSM"

    with open_session() as session:

        iv, ciphertext = encrypt_aes(
            session,
            plaintext
        )

        decrypted = decrypt_aes(
            session,
            iv,
            ciphertext
        )

        print("=== AES ENCRYPT / DECRYPT ===")
        print()
        print("Plaintext :", plaintext.decode())
        print("IV        :", iv.hex())
        print("Ciphertext:", ciphertext.hex())
        print("Decrypted :", decrypted.decode())


if __name__ == "__main__":
    main()