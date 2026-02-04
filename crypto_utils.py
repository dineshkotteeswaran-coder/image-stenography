"""
AES-256-CBC encrypt/decrypt for stego payload DATA only.
Key derived from password via SHA-256. IV random 16 bytes, prepended to ciphertext.
Encryption is performed ONLY inside build_payload(); never in embed_lsb().
"""
import hashlib
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

BLOCK_SIZE = 16
KEY_SIZE = 32  # AES-256

# Payload format: STEGO|<ENC_FLAG>|<FILE_TYPE>|<FILE_SIZE>|<DATA>
STEGO_PREFIX = b"STEGO|"
ENC_FLAG_ENC = b"ENC"
ENC_FLAG_NOENC = b"NOENC"


def _derive_key(user_key: str) -> bytes:
    return hashlib.sha256(user_key.encode("utf-8")).digest()


def encrypt_body(user_key: str, data: bytes) -> bytes:
    """Encrypt data with AES-256-CBC. Returns IV (16 bytes) + ciphertext."""
    if not data:
        return data
    key = _derive_key(user_key)
    iv = os.urandom(BLOCK_SIZE)
    padder = padding.PKCS7(BLOCK_SIZE * 8).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return iv + ct


def decrypt_body(user_key: str, data: bytes) -> bytes:
    """Decrypt data (IV + ciphertext). Raises ValueError on invalid key/ciphertext."""
    if not data or len(data) <= BLOCK_SIZE:
        raise ValueError("Invalid key or data not encrypted")
    key = _derive_key(user_key)
    iv = data[:BLOCK_SIZE]
    ct = data[BLOCK_SIZE:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def payload_size_bytes(original_data_len: int, file_type: str, password: str | None) -> int:
    """
    Calculate payload size AFTER encryption (if password exists).
    Used by Adaptive Image Capacity Enhancement to decide if upscaling is needed.
    Matches exactly the length that build_payload() returns.
    """
    enc_flag = ENC_FLAG_ENC if (password and password.strip()) else ENC_FLAG_NOENC
    file_type_clean = (file_type or "bin").strip().lower()
    file_size_str = str(original_data_len)
    header_len = (
        len(STEGO_PREFIX)
        + len(enc_flag)
        + 1
        + len(file_type_clean.encode("ascii"))
        + 1
        + len(file_size_str.encode("ascii"))
        + 1
    )
    if password and password.strip():
        # AES-256-CBC: IV (16) + ciphertext (PKCS7 padded to multiple of 16)
        padded_len = ((original_data_len + 15) // 16) * 16
        data_len = BLOCK_SIZE + padded_len
    else:
        data_len = original_data_len
    return header_len + data_len


def build_payload(data: bytes, file_type: str, password: str | None) -> bytes:
    """
    Build payload: STEGO|<ENC_FLAG>|<FILE_TYPE>|<FILE_SIZE>|<DATA>
    Encryption happens ONLY here; never in embed_lsb().
    """
    if not data:
        raise ValueError("Payload data is empty")
    enc_flag = ENC_FLAG_ENC if (password and password.strip()) else ENC_FLAG_NOENC
    file_type_clean = file_type.strip().lower() or "bin"
    file_size = len(data)
    if password and password.strip():
        data = encrypt_body(password, data)
    header = (
        STEGO_PREFIX
        + enc_flag
        + b"|"
        + file_type_clean.encode("ascii")
        + b"|"
        + str(file_size).encode("ascii")
        + b"|"
    )
    return header + data
