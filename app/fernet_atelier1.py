import os
import sys
from cryptography.fernet import Fernet


def get_fernet():
    """
    Récupère la clé Fernet depuis la variable d'environnement FERNET_KEY
    (stockée dans un GitHub Secret).
    """
    key = os.environ.get("FERNET_KEY")

    if not key:
        raise ValueError(
            "La variable d'environnement FERNET_KEY n'est pas définie. "
            "Vérifiez votre Secret GitHub."
        )

    return Fernet(key.encode())


def encrypt_file(input_file, output_file):
    """
    Chiffre un fichier et écrit le résultat dans output_file.
    """
    fernet = get_fernet()

    with open(input_file, "rb") as f:
        data = f.read()

    encrypted = fernet.encrypt(data)

    with open(output_file, "wb") as f:
        f.write(encrypted)

    print(f"Fichier chiffré : {output_file}")


def decrypt_file(input_file, output_file):
    """
    Déchiffre un fichier et écrit le résultat dans output_file.
    """
    fernet = get_fernet()

    with open(input_file, "rb") as f:
        data = f.read()

    decrypted = fernet.decrypt(data)

    with open(output_file, "wb") as f:
        f.write(decrypted)

    print(f"Fichier déchiffré : {output_file}")


def main():
    if len(sys.argv) != 4:
        print("Usage:")
        print("  python app/fernet_atelier1.py encrypt <input> <output>")
        print("  python app/fernet_atelier1.py decrypt <input> <output>")
        sys.exit(1)

    action = sys.argv[1]
    input_file = sys.argv[2]
    output_file = sys.argv[3]

    if action == "encrypt":
        encrypt_file(input_file, output_file)
    elif action == "decrypt":
        decrypt_file(input_file, output_file)
    else:
        print("Action invalide. Utilisez 'encrypt' ou 'decrypt'.")
        sys.exit(1)


if __name__ == "__main__":
    main()
