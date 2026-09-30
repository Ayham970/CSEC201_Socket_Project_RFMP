# base64 converts bytes into text containing characters that are safe
# to include inside our comma-separated packets.
# It also converts that encoded text back into the original bytes.
# Base64 is encoding, NOT encryption.
import base64

# binascii provides the Error exception that we will catch if a
# received Base64 field contains invalid characters or padding.
import binascii

# struct converts numbers into binary bytes and back again.
# We will use it to create and read the four-byte packet length header.
import struct


# The smallest allowed packet body is four bytes.
# For example, "(CC)" contains four ASCII characters, each one byte.
# This size does NOT include the separate four-byte length header.
MIN_PACKET_SIZE = 4

# The largest allowed packet body is 2 MiB (2,097,152 bytes).
# This limit comes from our group's protocol document.
# Checking it prevents us from accepting an excessively large packet.
# Underscores make the number easier to read without changing its value.
MAX_PACKET_SIZE = 2_097_152


# This dictionary records the allowed number of fields AFTER the
# packet type. The packet type itself is not included in the count.
#
# Each value is a tuple of allowed counts.
# For example, (3,) means exactly three fields are allowed.
# The comma makes it a one-item tuple.
# (0, 1) means either zero fields or one field is allowed.
FIELD_COUNTS = {
    # Start: protocol name, version, and security flag.
    # Example: (SS,RFMP,v1.0,0)
    "SS": (3,),

    # Connection confirmation:
    # Zero fields for an unsecured connection: (CC)
    # One field containing the server public key for secured setup.
    "CC": (0, 1),

    # Encryption setup: algorithm, encrypted session key,
    # and credentials containing username:client_public_key.
    # The credentials count as ONE comma-separated field.
    "EC": (3,),

    # Command: command type and its argument.
    # Example: command type "openRead" and an encoded filename.
    "CM": (2,),

    # Data: one field containing the Base64-encoded file payload.
    # An empty payload still counts as one field: (DP,)
    "DP": (1,),

    # Success: one encoded message or command-output field.
    "SC": (1,),

    # Error: an error code and an encoded description.
    "EE": (2,),

    # End: no additional fields, so the complete body is (End).
    # The capital E and lowercase nd must match the protocol exactly.
    "End": (0,),
}


# Define our own exception for malformed received packets or
# invalid Base64 fields.
#
# It inherits from ValueError because these errors involve invalid
# values or formats. The client/server can specifically catch
# ProtocolError and decide how to handle the failed communication.
class ProtocolError(ValueError):
    """Raised when a received packet or Base64 field is invalid."""

    # No extra behavior is needed: we use ValueError's existing
    # behavior while giving this exception a protocol-specific name.
    pass

def recv_exact(sock, byte_count):
    """Receive exactly byte_count bytes or raise EOFError."""

    # The requested byte count must be an integer.
    # Reject Boolean values too, because Python treats True and False
    # as integers, even though they are not meaningful counts here.
    if not isinstance(byte_count, int) or isinstance(byte_count, bool):
        raise ValueError("byte_count must be an integer")

    # A negative number of bytes cannot be received.
    if byte_count < 0:
        raise ValueError("byte_count cannot be negative")

    # Create an empty, changeable collection of bytes.
    # We will add each received chunk to this collection.
    data = bytearray()

    # TCP may deliver the requested data in several smaller chunks.
    # Keep receiving until we have collected the full requested amount.
    # If byte_count is zero, this loop is skipped automatically.
    while len(data) < byte_count:

        # Calculate how many bytes are still missing.
        # Requesting only this amount prevents us from accidentally
        # consuming bytes belonging to the next packet.
        remaining = byte_count - len(data)

        # Receive up to the remaining number of bytes.
        # recv() may return fewer bytes, so we must keep looping.
        chunk = sock.recv(remaining)

        # An empty result, b"", means the other side has closed
        # its sending connection. It does not mean "try again".
        # Since we still need bytes, the transmission is incomplete.
        if not chunk:
            raise EOFError(
                f"Connection closed after receiving "
                f"{len(data)} of {byte_count} expected bytes"
            )

        # Append this chunk to the bytes already collected.
        data.extend(chunk)

    # Convert the changeable bytearray into a bytes object.
    # For a zero-byte request, this returns b"".
    return bytes(data)

def _validate_parts(packet_type, fields):
    """Check the packet's structure without checking field meanings."""

    # The leading underscore in this function's name means it is
    # intended as an internal helper for other functions in this file.

    # The packet type must be a string and must match one of the
    # exact names in FIELD_COUNTS, such as "SS", "DP", or "End".
    if not isinstance(packet_type, str):
        raise ValueError("Packet type must be a string")

    if packet_type not in FIELD_COUNTS:
        raise ValueError("Unknown RFMP packet type")

    # Our shared interface requires a list of prepared field strings.
    # Variable content, such as filenames, must already be Base64-encoded.
    if not isinstance(fields, list):
        raise ValueError("Fields must be provided as a list")

    # Look up the allowed field counts for this packet type.
    # For example, CC permits either zero fields or one field.
    allowed_counts = FIELD_COUNTS[packet_type]

    # Reject packets containing too many or too few fields.
    if len(fields) not in allowed_counts:
        raise ValueError(f"Wrong number of fields for {packet_type}")

    # Check each field separately.
    for field in fields:

        # Every prepared field must be text.
        # Raw bytes must first be converted using encode_field().
        if not isinstance(field, str):
            raise ValueError("Each field must be a string")

        # Check every character in the prepared field.
        # An empty field has no characters, so it passes this check.
        # This is necessary for valid empty-data packets such as (DP,).
        for character in field:

            # ord() returns a character's numeric Unicode value.
            # Values 33 through 126 are printable ASCII characters,
            # excluding spaces. This rejects spaces, tabs, newlines,
            # null characters, and non-ASCII characters.
            if ord(character) < 33 or ord(character) > 126:
                raise ValueError(
                    "Fields must contain printable ASCII without spaces"
                )

            # Commas separate fields, and parentheses surround packets.
            # Allowing them inside a field would break packet parsing.
            # Base64 encoding keeps these characters out of variable data.
            if character in ",()":
                raise ValueError(
                    "Fields cannot contain commas or parentheses"
                )

    # A colon is allowed because EC uses it to separate the encoded
    # username from the encoded client public key within one field.
    #
    # This helper checks structure only. The client/server checks
    # meanings such as the protocol version and chosen encryption mode.
    # If every check passes, the function finishes normally.

def send_packet(sock, packet_type, fields):
    """Build, validate, and send one complete RFMP packet."""

    # Check the packet type, number of fields, and field characters.
    # If anything is invalid, this raises ValueError before we send data.
    _validate_parts(packet_type, fields)

    # Combine the packet type and prepared fields into one list.
    # Example: ["SS"] + ["RFMP", "v1.0", "0"]
    # becomes ["SS", "RFMP", "v1.0", "0"].
    parts = [packet_type] + fields

    # Join the parts with commas and surround them with parentheses.
    # Example result: "(SS,RFMP,v1.0,0)"
    # An empty fields list produces "(CC)" for packet type CC.
    # One empty field produces "(DP,)" for packet type DP.
    body_text = "(" + ",".join(parts) + ")"

    # Convert the packet text into bytes for transmission.
    # All prepared fields have already been checked for ASCII characters.
    body = body_text.encode("ascii")

    # Measure only the body bytes, excluding the four-byte header.
    body_length = len(body)

    # Reject a packet whose body is outside the agreed size limits.
    if not MIN_PACKET_SIZE <= body_length <= MAX_PACKET_SIZE:
        raise ValueError("Packet body length is outside the RFMP limits")

    # Convert the body length into exactly four binary bytes.
    # "!" means network byte order (big-endian).
    # "I" means a four-byte unsigned integer with this format.
    # For a body length of 16, the header bytes are 00 00 00 10.
    header = struct.pack("!I", body_length)

    # Place the header immediately before the packet body.
    # Do not add a newline or a null terminator.
    frame = header + body

    # sendall() keeps sending until the complete frame has been sent
    # or a socket error occurs. A single send() might send only part.
    # Socket errors propagate so the client/server can handle them.
    sock.sendall(frame)

def receive_packet(sock):
    """Receive and validate one RFMP packet, keeping fields encoded."""

    # Every frame begins with a four-byte header.
    # recv_exact() keeps reading until all four bytes arrive.
    # If the connection closes early, EOFError propagates to the caller.
    header = recv_exact(sock, 4)

    # Convert the binary header back into the packet body's length.
    # "!I" matches the format used by send_packet().
    # unpack() returns a tuple, so [0] selects its first value.
    body_length = struct.unpack("!I", header)[0]

    # Validate the advertised size BEFORE receiving the body.
    # This prevents accepting a body larger than our protocol permits.
    if not MIN_PACKET_SIZE <= body_length <= MAX_PACKET_SIZE:
        raise ProtocolError(
            "Packet body length is outside the RFMP limits"
        )

    # Read exactly the body length stated in the header.
    # Any bytes belonging to a later packet remain in the socket.
    raw_body = recv_exact(sock, body_length)

    # Packet bodies must be ASCII because variable content is
    # Base64-encoded before being placed inside the packet.
    try:
        body = raw_body.decode("ascii")

    # Convert an ASCII decoding failure into our protocol exception.
    # "from exc" preserves the original error for debugging.
    except UnicodeDecodeError as exc:
        raise ProtocolError("Packet body must be ASCII") from exc

    # Check that the packet has its required outer parentheses.
    # Extra spaces or newlines outside them are not accepted.
    if not body.startswith("(") or not body.endswith(")"):
        raise ProtocolError("Packet must have outer parentheses")

    # Remove only the first and last characters: the parentheses.
    # Example: "(CM,openRead,ZmlsZS50eHQ=)"
    # becomes "CM,openRead,ZmlsZS50eHQ=".
    inner_body = body[1:-1]

    # Split the remaining text at commas.
    # Using an explicit comma preserves empty fields:
    # "DP," becomes ["DP", ""], which represents an empty payload.
    parts = inner_body.split(",")

    # The first item is the packet type.
    packet_type = parts[0]

    # All remaining items are the packet's fields.
    # For "(CC)", this produces an empty list.
    fields = parts[1:]

    # Reuse our helper to check the type, field count, and characters.
    try:
        _validate_parts(packet_type, fields)

    # Invalid received data must raise ProtocolError.
    # Local mistakes in send_packet() instead raise ValueError.
    except ValueError as exc:
        raise ProtocolError(str(exc)) from exc

    # Return the type and fields together as a tuple.
    # Fields remain in their wire form: no Base64 decoding or
    # decryption happens here. The client/server handles that next.
    return packet_type, fields  

def encode_field(data):
    """Convert bytes into standard Base64 text for a packet field."""

    # This function expects bytes, not a normal text string.
    # For text, the caller first uses .encode("utf-8").
    # Example: encode_field("hello".encode("utf-8"))
    if not isinstance(data, bytes):
        raise TypeError("encode_field expects bytes")

    # Convert the original bytes into Base64-encoded bytes.
    # Standard Base64 does not contain commas or parentheses,
    # so it will not interfere with our packet structure.
    encoded_bytes = base64.b64encode(data)

    # Convert the Base64 bytes into an ASCII string so that
    # send_packet() can combine it with the other fields.
    # b64encode() adds any required "=" padding and no newlines.
    return encoded_bytes.decode("ascii")


def decode_field(text):
    """Strictly decode a standard Base64 field into its original bytes."""

    # Received packet fields should be strings.
    # Reject other input types with our protocol-specific exception.
    if not isinstance(text, str):
        raise ProtocolError("Base64 field must be a string")

    try:
        # Base64 contains only ASCII characters.
        # Non-ASCII input causes UnicodeEncodeError.
        encoded_bytes = text.encode("ascii")

        # validate=True rejects invalid Base64 characters instead
        # of silently ignoring them. It also checks padding.
        decoded_bytes = base64.b64decode(
            encoded_bytes,
            validate=True
        )

    # Invalid characters or padding can cause binascii.Error.
    # Convert decoding failures into ProtocolError so the
    # client/server can handle them consistently.
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ProtocolError("Invalid Base64 field") from exc

    # Encode the result again and compare it with the original.
    # This catches nonstandard forms that the decoder may accept,
    # such as unnecessary padding or invalid unused padding bits.
    if encode_field(decoded_bytes) != text:
        raise ProtocolError("Base64 field must use standard padding")

    # Return raw bytes. The caller decides whether to decrypt them
    # or decode them as UTF-8 text, depending on the packet field.
    # An empty Base64 string correctly returns b"".
    return decoded_bytes  
