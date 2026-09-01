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

                print(f"{attribute.name:15} : {value}")

            except Exception as error:
                print(
                    f"{attribute.name:15} : "
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

                print(f"{attribute.name:15} : {value}")

            except Exception as error:
                print(
                    f"{attribute.name:15} : "
                    f"No disponible ({type(error).__name__})"
                )


if __name__ == "__main__":
    inspect_private_key()

    print()
    print("=" * 40)
    print()

    inspect_public_key()