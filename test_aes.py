import pkcs11

from hsm.connection import open_session
from hsm.aes import generate_aes_key

# Solo se ejecuta una vez, ya que genera la clave AES.
# El atributo store=true, guarda esa clave en el token ---  

def main():
    with open_session(read_write=True) as session:
        key = generate_aes_key(session)
        print("Clave AES generada correctamente")
        print("Label:", key[pkcs11.Attribute.LABEL])


if __name__ == "__main__":
    main()