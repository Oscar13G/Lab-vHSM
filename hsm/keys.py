from pkcs11 import Attribute, ObjectClass

from hsm.connection import open_session


def list_keys():
    with open_session() as session:

        print("=== Claves privadas ===")

        private_keys = session.get_objects({
            Attribute.CLASS: ObjectClass.PRIVATE_KEY
        })

        for key in private_keys:
            print(
                f"Label: {key[Attribute.LABEL]} | "
                f"ID: {key[Attribute.ID].hex()}"
            )

        print()

        print("=== Claves públicas ===")

        public_keys = session.get_objects({
            Attribute.CLASS: ObjectClass.PUBLIC_KEY
        })

        for key in public_keys:
            print(
                f"Label: {key[Attribute.LABEL]} | "
                f"ID: {key[Attribute.ID].hex()}"
            )


if __name__ == "__main__":
    list_keys()