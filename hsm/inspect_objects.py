from pkcs11 import Attribute, ObjectClass

from hsm.connection import open_session


def inspect_public_key():

    with open_session() as session:

        public_key = session.get_key(
            object_class=ObjectClass.PUBLIC_KEY,
            label="LAB-RSA-SIGNING"
        )

        print("=== PUBLIC KEY ===")
        print()

        attributes = [
            Attribute.CLASS,
            Attribute.LABEL,
            Attribute.ID,
            Attribute.KEY_TYPE,
            Attribute.VERIFY,
            Attribute.ENCRYPT,
            Attribute.WRAP,
            Attribute.TOKEN,
            Attribute.PRIVATE,
            Attribute.LOCAL,
        ]

        for attribute in attributes:
            try:
                value = public_key[attribute]

                if attribute == Attribute.ID:
                    value = value.hex()

                print(f"{attribute.name:18} : {value}")

            except Exception as error:
                print(
                    f"{attribute.name:18} : "
                    f"No disponible ({type(error).__name__})"
                )


def inspect_private_key():

    with open_session() as session:

        private_key = session.get_key(
            object_class=ObjectClass.PRIVATE_KEY,
            label="LAB-RSA-SIGNING"
        )

        print("=== PRIVATE KEY ===")
        print()

        attributes = [
            Attribute.CLASS,
            Attribute.LABEL,
            Attribute.ID,
            Attribute.KEY_TYPE,
            Attribute.SIGN,
            Attribute.DECRYPT,
            Attribute.SENSITIVE,
            Attribute.EXTRACTABLE,
            Attribute.TOKEN,
            Attribute.PRIVATE,
            Attribute.LOCAL,
            Attribute.ALWAYS_SENSITIVE,
            Attribute.NEVER_EXTRACTABLE,
            Attribute.VERIFY,
            Attribute.ENCRYPT,
            Attribute.UNWRAP,
        ]

        for attribute in attributes:
            try:
                value = private_key[attribute]

                if attribute == Attribute.ID:
                    value = value.hex()

                print(f"{attribute.name:18} : {value}")

            except Exception as error:
                print(
                    f"{attribute.name:18} : "
                    f"No disponible ({type(error).__name__})"
                )


def inspect_aes_key():
    """
    Inspecciona los atributos principales de la clave AES del laboratorio.
    """

    with open_session() as session:

        aes_key = session.get_key(
            object_class=ObjectClass.SECRET_KEY,
            label="LAB-AES-256"
        )

        print("=== AES SECRET KEY ===")
        print()

        attributes = [
            Attribute.CLASS,
            Attribute.LABEL,
            Attribute.ID,
            Attribute.KEY_TYPE,

            # Operaciones criptográficas permitidas.
            Attribute.ENCRYPT,
            Attribute.DECRYPT,

            # Controles de protección del material secreto.
            Attribute.SENSITIVE,
            Attribute.EXTRACTABLE,
            Attribute.ALWAYS_SENSITIVE,
            Attribute.NEVER_EXTRACTABLE,

            # Propiedades del objeto dentro del token.
            Attribute.TOKEN,
            Attribute.PRIVATE,
            Attribute.LOCAL,

            # Nos sirve para saber si la clave podría usarse
            # posteriormente para proteger otras claves.
            Attribute.WRAP,
            Attribute.UNWRAP,
        ]

        for attribute in attributes:
            try:
                value = aes_key[attribute]

                if attribute == Attribute.ID:
                    value = value.hex()

                print(f"{attribute.name:18} : {value}")

            except Exception as error:
                print(
                    f"{attribute.name:18} : "
                    f"No disponible ({type(error).__name__})"
                )


if __name__ == "__main__":

    inspect_private_key()

    print()
    print("=" * 40)
    print()

    inspect_public_key()

    print()
    print("=" * 40)
    print()

    inspect_aes_key()