"""Local tests for RFMP RSA exchange and payload ciphers."""

from crypto_utils import (
    decrypt_payload,
    decrypt_session_key,
    encrypt_payload,
    encrypt_session_key,
    generate_rsa_keypair,
    generate_session_key,
    load_public_key,
    serialize_public_key,
)

private_key, public_key = generate_rsa_keypair()
loaded_public_key = load_public_key(serialize_public_key(public_key))

for mode in ("AES", "CAESAR"):
    session_key = generate_session_key(mode)
    encrypted_key = encrypt_session_key(loaded_public_key, session_key)
    assert decrypt_session_key(private_key, encrypted_key) == session_key

    for content in (b"", b"First line\nSecond line\nThird line\n"):
        encrypted = encrypt_payload(content, mode, session_key)
        assert decrypt_payload(encrypted, mode, session_key) == content

none_key = generate_session_key("NONE")
for content in (b"", b"First line\nSecond line\nThird line\n"):
    encrypted = encrypt_payload(content, "NONE", none_key)
    assert decrypt_payload(encrypted, "NONE", none_key) == content

print("PASS: RSA session-key exchange")
print("PASS: NONE, AES-GCM, and Caesar empty content")
print("PASS: NONE, AES-GCM, and Caesar multiline content")
