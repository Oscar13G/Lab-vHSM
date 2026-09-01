from hsm.connection import open_session


def main():
    with open_session() as session:
        print("Sesión PKCS#11 abierta correctamente")
        print(session)


if __name__ == "__main__":
    main()