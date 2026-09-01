import os

PKCS11_LIB = "/usr/lib/softhsm/libsofthsm2.so"
TOKEN_LABEL = "LAB-HSM"

HSM_USER_PIN = os.getenv("HSM_USER_PIN")