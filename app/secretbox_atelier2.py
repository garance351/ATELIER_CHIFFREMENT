import os
import sys
from nacl import secret, utils
from nacl.exceptions import CryptoError


KEY_ENV = "SECRETBOX_KEY"


def get_secretbox():
    """
    Récupère la clé depuis la variable d'environnement SECRETBOX_KEY.
    La clé doit être en base64 et faire 32 bytes une fois décodée.
    """
    import base64

    key_b64 = os.environ.get(KEY_ENV)
    if not key_b64:
        raise ValueError(
            "La variable d'environnement SECRETBOX_KEY n'est pas définie."
        )

    key = base64.b64decode(key_b64)

    if len(key) != secret.SecretBox.KEY_SIZE:
        raise ValueError("La clé doit faire 32 bytes.")

    return secret.SecretBox(key)


def encrypt_file(input_file, output_file):
    box = get_secretbox()

    with open(input_file, "rb") as f:
        data = f.read()

    nonce = utils.random(secret.SecretBox.NONCE_SIZE)

    encrypted = box.encrypt(data, nonce)

    with open(output_file, "wb") as f:
        f.write(encrypted)

    print(f"Fichier chiffré : {output_file}")


def decrypt_file(input_file, output_file):
    box = get_secretbox()

    with open(input_file, "rb") as f:
        encrypted = f.read()

    try:
        decrypted = box.decrypt(encrypted)
    except CryptoError:
        print("Erreur : déchiffrement impossible (clé invalide ou données corrompues).")
        sys.exit(1)

    with open(output_file, "wb") as f:
        f.write(decrypted)

    print(f"Fichier déchiffré : {output_file}")


def main():
    if len(sys.argv) != 4:
        print("Usage:")
        print("  python secretbox_atelier2.py encrypt <input> <output>")
        print("  python secretbox_atelier2.py decrypt <input> <output>")
        sys.exit(1)

    action = sys.argv[1]
    input_file = sys.argv[2]
    output_file = sys.argv[3]

    if action == "encrypt":
        encrypt_file(input_file, output_file)
    elif action == "decrypt":
        decrypt_file(input_file, output_file)
    else:
        print("Action invalide.")
        sys.exit(1)


if __name__ == "__main__":
    main()
