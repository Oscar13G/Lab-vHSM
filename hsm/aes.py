import pkcs11

from pkcs11 import KeyType


def generate_aes_key(session):
    """
    Genera una clave AES-256 persistente dentro del HSM.
    """
    key = session.generate_key(
        KeyType.AES,
        256,
        label="LAB-AES-256",
        store=True,
        template={
            pkcs11.Attribute.ENCRYPT: True,
            pkcs11.Attribute.DECRYPT: True,
            pkcs11.Attribute.SENSITIVE: True,
            pkcs11.Attribute.EXTRACTABLE: False,
        },
    )

    return key