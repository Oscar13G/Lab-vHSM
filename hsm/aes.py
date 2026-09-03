import pkcs11

from pkcs11 import KeyType, ObjectClass, Mechanism

AES_KEY_LABEL = "LAB-AES-256"
#AES_KEY_LABEL = "LAB-AES-2561"


def get_aes_key(session):
    """
    Localiza la clave AES persistente almacenada en el HSM.
    """
    return session.get_key(
        object_class=ObjectClass.SECRET_KEY,
        key_type=KeyType.AES,
        label=AES_KEY_LABEL,
    )

def encrypt_aes(session, plaintext):
    """
    Cifra datos usando LAB-AES-256 mediante AES-CBC-PAD.
    """

    key = get_aes_key(session)

    # AES utiliza bloques de 128 bits, por lo que CBC requiere
    # un IV de 128 bits generado aleatoriamente.
    iv = session.generate_random(128)

    ciphertext = key.encrypt(
        plaintext,
        mechanism=Mechanism.AES_CBC_PAD,
        mechanism_param=iv,
    )

    # Necesitaremos el mismo IV para poder descifrar después.
    return iv, ciphertext

def decrypt_aes(session, iv, ciphertext):
    """
    Descifra datos usando LAB-AES-256 mediante AES-CBC-PAD.
    """

    key = get_aes_key(session)

    # Para CBC necesitamos reutilizar exactamente el mismo IV
    # que se usó durante el cifrado.
    plaintext = key.decrypt(
        ciphertext,
        mechanism=Mechanism.AES_CBC_PAD,
        mechanism_param=iv,
    )

    return plaintext

def generate_aes_key(session):
    """
    Genera una clave AES-256 persistente dentro del HSM.
    """
    key = session.generate_key(
        KeyType.AES,
        256,
        label=AES_KEY_LABEL,
        store=True,
        template={
            # Operaciones permitidas para esta clave.
            pkcs11.Attribute.ENCRYPT: True,
            pkcs11.Attribute.DECRYPT: True,

            # El material secreto no puede extraerse en claro del HSM.
            pkcs11.Attribute.SENSITIVE: True,
            pkcs11.Attribute.EXTRACTABLE: False,
        },
    )

    return key