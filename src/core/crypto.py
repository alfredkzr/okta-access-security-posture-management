from cryptography.fernet import Fernet

from src.config import settings


def encrypt_token(plaintext: str) -> bytes:
    f = Fernet(settings.encryption_key.encode())
    return f.encrypt(plaintext.encode())


def decrypt_token(ciphertext: bytes) -> str:
    f = Fernet(settings.encryption_key.encode())
    return f.decrypt(ciphertext).decode()
