def _validate_none_mode(mode, session_key):
    """Validate the mode and session key used for NONE encryption."""

    # NONE means that file contents are transferred without encryption.
    # The mode name is case-sensitive and must be exactly "NONE".
    if mode != "NONE":
        raise ValueError("This version currently supports NONE mode only")

    # According to our protocol, NONE mode uses an empty bytes object
    # as its session key because no encryption key is required.
    if not isinstance(session_key, bytes):
        raise TypeError("The session key must be bytes")

    if session_key != b"":
        raise ValueError("NONE mode requires an empty session key")

def generate_session_key(mode):
    """Generate and return the session key required by the selected mode."""

    # Call our validation helper to confirm that the requested mode
    # is currently supported and uses the correct empty key.
    #
    # We pass b"" because NONE mode does not use encryption and
    # therefore does not need a secret session key.
    _validate_none_mode(mode, b"")

    # Return an empty bytes object as required by the protocol.
    # This is bytes, not an empty normal string.
    return b""

def encrypt_payload(data, mode, session_key):
    """Return the payload unchanged when NONE mode is selected."""

    # Validate that the selected mode is exactly "NONE" and that
    # its session key is the required empty bytes object, b"".
    _validate_none_mode(mode, session_key)

    # File contents must be bytes because sockets and Base64 helpers
    # work with bytes rather than normal Python strings.
    #
    # For text from a string, the caller must first use:
    # text.encode("utf-8")
    if not isinstance(data, bytes):
        raise TypeError("Payload data must be bytes")

    # NONE mode performs no encryption.
    # Return the exact same bytes without changing their contents.
    #
    # Base64 encoding is performed separately by encode_field()
    # in packets.py after this function returns.
    return data

def decrypt_payload(data, mode, session_key):
    """Return the original payload unchanged in NONE mode."""

    # NONE mode does not perform encryption or decryption.
    # The validation and byte checks are identical to encrypt_payload(),
    # so we reuse that function instead of repeating the same code.
    #
    # This also ensures that encryption and decryption handle invalid
    # modes, incorrect keys, and non-byte data consistently.
    return encrypt_payload(data, mode, session_key)
