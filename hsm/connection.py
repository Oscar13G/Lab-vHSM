import pkcs11

from config import PKCS11_LIB, TOKEN_LABEL, HSM_USER_PIN


def get_library():
    """
    Carga la biblioteca PKCS#11 del HSM.
    """
    return pkcs11.lib(PKCS11_LIB)


def get_token():
    """
    Localiza el token configurado por su label.
    """
    library = get_library()

    return library.get_token(
        token_label=TOKEN_LABEL
    )


def open_session():
    """
    Abre una sesión autenticada contra el token.
    """
    if not HSM_USER_PIN:
        raise RuntimeError(
            "La variable de entorno HSM_USER_PIN no está definida"
        )

    token = get_token()

    return token.open(
        user_pin=HSM_USER_PIN
    )