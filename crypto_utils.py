"""RFMP cryptographic helpers. Base64 and socket work stay in packets.py."""

import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537
AES_KEY_SIZE = 32
AES_NONCE_SIZE = 12


def generate_rsa_keypair():
    """Return a fresh (private_key, public_key) RSA pair."""
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
    )
    return private_key, private_key.public_key()


def _validate_public_key(public_key):
    """Require the RSA public-key type and parameters agreed by the team."""
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Public key must be an RSA public key")
    if public_key.key_size != RSA_KEY_SIZE:
        raise ValueError("RSA public key must be 2048 bits")
    if public_key.public_numbers().e != RSA_PUBLIC_EXPONENT:
        raise ValueError("RSA public exponent must be 65537")


def _validate_private_key(private_key):
    """Require the matching RFMP RSA private-key parameters."""
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Private key must be an RSA private key")
    public_numbers = private_key.private_numbers().public_numbers
    if private_key.key_size != RSA_KEY_SIZE or public_numbers.e != RSA_PUBLIC_EXPONENT:
        raise ValueError("RSA private key must use the RFMP parameters")


def serialize_public_key(public_key):
    """Return DER SubjectPublicKeyInfo bytes without Base64 encoding."""
    _validate_public_key(public_key)
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_public_key(serialized_key):
    """Load DER public-key bytes and validate the RSA parameters."""
    if not isinstance(serialized_key, bytes):
        raise TypeError("Serialized public key must be bytes")
    public_key = serialization.load_der_public_key(serialized_key)
    _validate_public_key(public_key)
    return public_key


def generate_session_key(mode):
    """Generate the agreed session key for NONE, AES, or CAESAR."""
    if mode == "NONE":
        return b""
    if mode == "AES":
        # AES-256 uses exactly 32 unpredictable random bytes.
        return os.urandom(AES_KEY_SIZE)
    if mode == "CAESAR":
        # Caesar uses one numeric byte with a value from 1 through 25.
        return bytes([int.from_bytes(os.urandom(1), "big") % 25 + 1])
    raise ValueError(f"Unknown encryption mode: {mode!r}")


def encrypt_session_key(server_public_key, session_key):
    """Wrap a session key using RSA-OAEP with SHA-256."""
    _validate_public_key(server_public_key)
    if not isinstance(session_key, bytes):
        raise TypeError("Session key must be bytes")
    return server_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_session_key(server_private_key, encrypted_key):
    """Recover a session key using the matching RSA private key."""
    _validate_private_key(server_private_key)
    if not isinstance(encrypted_key, bytes):
        raise TypeError("Encrypted session key must be bytes")
    return server_private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def _validate_payload_inputs(data, mode, session_key):
    """Check byte types, supported mode, and the session-key format."""
    if not isinstance(data, bytes):
        raise TypeError("Payload must be bytes")
    if not isinstance(session_key, bytes):
        raise TypeError("Session key must be bytes")
    if mode == "NONE" and session_key != b"":
        raise ValueError("NONE mode requires an empty session key")
    if mode == "AES" and len(session_key) != AES_KEY_SIZE:
        raise ValueError("AES mode requires a 32-byte session key")
    if mode == "CAESAR" and (
        len(session_key) != 1 or not 1 <= session_key[0] <= 25
    ):
        raise ValueError("CAESAR mode requires one shift byte from 1 through 25")
    if mode not in ("NONE", "AES", "CAESAR"):
        raise ValueError(f"Unknown encryption mode: {mode!r}")


def encrypt_payload(data, mode, session_key):
    """Return a raw encrypted payload for later Base64 encoding."""
    _validate_payload_inputs(data, mode, session_key)
    if mode == "NONE":
        return data
    if mode == "AES":
        # A new 12-byte nonce is required for every AES-GCM payload.
        nonce = os.urandom(AES_NONCE_SIZE)
        ciphertext_and_tag = AESGCM(session_key).encrypt(nonce, data, None)
        return nonce + ciphertext_and_tag
    return _caesar_shift(data, session_key[0])


def decrypt_payload(data, mode, session_key):
    """Return original bytes and authenticate AES-GCM data."""
    _validate_payload_inputs(data, mode, session_key)
    if mode == "NONE":
        return data
    if mode == "AES":
        # Empty plaintext still produces a 12-byte nonce and 16-byte tag.
        if len(data) < AES_NONCE_SIZE + 16:
            raise ValueError("AES payload is too short")
        nonce = data[:AES_NONCE_SIZE]
        ciphertext_and_tag = data[AES_NONCE_SIZE:]
        return AESGCM(session_key).decrypt(nonce, ciphertext_and_tag, None)
    return _caesar_shift(data, -session_key[0])


def _caesar_shift(data, shift):
    """Shift ASCII letters while preserving every other byte."""
    result = bytearray()
    for value in data:
        if ord("A") <= value <= ord("Z"):
            value = (value - ord("A") + shift) % 26 + ord("A")
        elif ord("a") <= value <= ord("z"):
            value = (value - ord("a") + shift) % 26 + ord("a")
        result.append(value)
    return bytes(result)
