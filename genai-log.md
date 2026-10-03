# GenAI Prompts and Output (with comments)

**Tools used:**
- ChatGPT: the encryption algorithms in `crypto_utils.py` (Parts 1 to 3)
- Claude: using the encryption in the server and the Python client, and the Base64 code in the C client (Parts 4 to 6)

**Library:** Python `cryptography` package (tested with version 46.0.7)

The code was generated with AI and then reviewed and tested by the team. Each part below shows the prompt, the generated code, and our explanation of how it works.

The code is taken from our project files. The comments are ours. Input-validation checks and unrelated lines are left out to keep it short (shown as `...`); the full files are included with the submission.

---

## Part 1: RSA (key pair and session key encryption)

### Prompt 

> Write Python code using the cryptography library to generate RSA keys and use them to encrypt and decrypt a session key.

### Output (generated code, with our comments)

```python
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

RSA_KEY_SIZE = 2048          # 2048-bit RSA keys (secure size)
RSA_PUBLIC_EXPONENT = 65537  # standard public exponent used by RSA


def generate_rsa_keypair():
    # Create a new private key. The public key is calculated from it.
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
    )
    return private_key, private_key.public_key()


def serialize_public_key(public_key):
    # Convert the public key object into bytes (DER format)
    # so it can be sent inside the CC and EC packets.
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_public_key(serialized_key):
    # Turn the received bytes back into a public key object.
    return serialization.load_der_public_key(serialized_key)


def encrypt_session_key(server_public_key, session_key):
    # CLIENT side: lock the session key with the server's PUBLIC key.
    # OAEP padding with SHA-256 adds randomness, so the same key
    # encrypts to different bytes each time.
    return server_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_session_key(server_private_key, encrypted_key):
    # SERVER side: unlock the session key with the server's PRIVATE key.
    # The padding settings must match the ones used for encryption.
    return server_private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
```

### Explanation

- RSA is **asymmetric**: the public key encrypts, and only the matching private key decrypts.
- The server sends its public key in `(CC,server_public_key)`. The client uses it to encrypt the session key and sends the result in the `EC` packet.
- Only the server has the private key, so only the server can recover the session key, even if someone captures the packet.
- RSA is slow and can only encrypt small data, so it is used only for the session key. The files are encrypted with AES or Caesar.

---

## Part 2: AES (file encryption)

### Prompt 

> Write Python code to encrypt and decrypt file contents with AES using the session key.

### Output (generated code, with our comments)

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AES_KEY_SIZE = 32    # 32 bytes = 256-bit AES key
AES_NONCE_SIZE = 12  # AES-GCM uses a 12-byte nonce


def generate_session_key(mode):
    if mode == "AES":
        # 32 random bytes from the operating system
        return os.urandom(AES_KEY_SIZE)
    ...


def encrypt_payload(data, mode, session_key):
    if mode == "AES":
        # A new random nonce for EVERY message, so the same file
        # encrypts differently each time.
        nonce = os.urandom(AES_NONCE_SIZE)
        # Encrypt and add a 16-byte authentication tag at the end
        ciphertext_and_tag = AESGCM(session_key).encrypt(nonce, data, None)
        # Send the nonce in front; the receiver needs it to decrypt
        return nonce + ciphertext_and_tag
    ...


def decrypt_payload(data, mode, session_key):
    if mode == "AES":
        # Smallest valid payload: 12-byte nonce + 16-byte tag
        if len(data) < AES_NONCE_SIZE + 16:
            raise ValueError("AES payload is too short")
        nonce = data[:AES_NONCE_SIZE]               # first 12 bytes
        ciphertext_and_tag = data[AES_NONCE_SIZE:]  # the rest
        # Decrypt and check the tag. If any byte was changed,
        # this raises an error instead of returning wrong data.
        return AESGCM(session_key).decrypt(nonce, ciphertext_and_tag, None)
    ...
```

### Explanation

- AES is **symmetric**: the same 32-byte session key encrypts and decrypts. Both sides have it after the RSA step.
- **GCM mode** adds an authentication tag, so the receiver can detect if the data was changed during transfer. The server then replies with error code 4 and does not save the file.
- The **nonce** must be new for every message. It is not secret, so it is sent together with the ciphertext.
- Packet contents: `nonce (12 bytes) + ciphertext + tag (16 bytes)`.

---

## Part 3: Caesar cipher (file encryption)

### Prompt 

> Write a Caesar cipher in Python that encrypts and decrypts text using a shift key.

### Output (generated code, with our comments)

```python
def generate_session_key(mode):
    if mode == "CAESAR":
        # One random byte, turned into a shift from 1 to 25
        return bytes([int.from_bytes(os.urandom(1), "big") % 25 + 1])
    ...


def encrypt_payload(data, mode, session_key):
    if mode == "CAESAR":
        # Shift forward by the key
        return _caesar_shift(data, session_key[0])
    ...


def decrypt_payload(data, mode, session_key):
    if mode == "CAESAR":
        # Shift backward by the same key
        return _caesar_shift(data, -session_key[0])
    ...


def _caesar_shift(data, shift):
    result = bytearray()
    for value in data:
        # Capital letters: shift inside A-Z and wrap around
        if ord("A") <= value <= ord("Z"):
            value = (value - ord("A") + shift) % 26 + ord("A")
        # Small letters: shift inside a-z and wrap around
        elif ord("a") <= value <= ord("z"):
            value = (value - ord("a") + shift) % 26 + ord("a")
        # Everything else (spaces, digits, punctuation) stays the same
        result.append(value)
    return bytes(result)
```

### Explanation

- Each letter moves forward by the key. With key 3, `Hello, Zz!` becomes `Khoor, Cc!`.
- `% 26` wraps around the alphabet, so `Z` + 3 becomes `C`.
- Decryption uses the same function with a negative shift.
- Caesar is **not secure**: there are only 25 possible keys, so an attacker can try all of them in seconds. It is included to compare a classical cipher with AES.

---

## Part 4: Encryption in the server (`ayham_server.py`)

### Prompt 

> How do I add the secured setup to my server, so it sends its public key, receives the encrypted session key, and uses it to encrypt and decrypt files?

### Output (generated code, with our comments)

```python
def secured_setup(clientsocket, session):
    # After (SS,RFMP,v1.0,1). Returns True if setup worked.

    # 1. Make the server RSA keys and send the public key: (CC,server_public_key)
    private_key, public_key = generate_rsa_keypair()
    send_packet(clientsocket, "CC", [encode_field(serialize_public_key(public_key))])

    # 2. Receive (EC,algorithm,encrypted_session_key,username:client_public_key)
    packet_type, fields = receive_packet(clientsocket)
    ...
    algorithm = fields[0]                     # "AES" or "CAESAR"
    username_field, client_key_field = fields[2].split(":")

    # 3. Decrypt the session key with the server PRIVATE key
    session_key = decrypt_session_key(private_key, decode_field(fields[1]))
    client_public_key = load_public_key(decode_field(client_key_field))

    # 4. Save everything in this client's session
    session["mode"] = algorithm
    session["session_key"] = session_key
    session["username"] = decode_field(username_field).decode()
    session["client_public_key"] = client_public_key

    send_success(clientsocket, "SETUP_COMPLETE")
    return True


# openRead: encrypt the file before sending it
data = encrypt_payload(data, session["mode"], session["session_key"])
send_packet(clientsocket, "DP", [encode_field(data)])

# openWrite: decrypt the received data before saving it
data = decrypt_payload(decode_field(fields[0]), session["mode"], session["session_key"])
```

### Explanation

- The server makes a **new RSA key pair for each client** and sends only the public key. The private key never leaves the server.
- After decrypting the session key, the server stores it in **that client's session**. Two clients can use different algorithms and keys at the same time.
- openRead encrypts the file before sending it, and openWrite decrypts the data before saving it, as the assignment requires. Files are stored on the server as plaintext.
- In NONE mode, `encrypt_payload` and `decrypt_payload` return the data unchanged, so the same code works for every mode.

---

## Part 5: Encryption in the Python client (`ayham_client.py`)

### Prompt 

> How do I add AES and Caesar options to my Python client, and send the session key to the server encrypted with RSA?

### Output (generated code, with our comments)

```python
mode = input("Choose NONE, AES or CAESAR: ").strip().upper()

# Session key: NONE = empty, AES = 32 random bytes, CAESAR = shift 1-25
key = generate_session_key(mode)
...
username = input("Username: ").strip()

# The client makes its own RSA key pair
private_key, public_key = generate_rsa_keypair()

# (SS,RFMP,v1.0,1) -> (CC,server_public_key)
send_packet(s, "SS", ["RFMP", "v1.0", "1"])
fields = get_reply("CC")

# Encrypt the session key with the server PUBLIC key
server_public_key = load_public_key(decode_field(fields[0]))
encrypted_key = encrypt_session_key(server_public_key, key)

# (EC,algorithm,encrypted_session_key,username:client_public_key)
credentials = encode_field(username.encode()) + ":" + encode_field(serialize_public_key(public_key))
send_packet(s, "EC", [mode, encode_field(encrypted_key), credentials])
...

# openRead: decrypt the data received from the server
data = decrypt_payload(decode_field(fields[0]), mode, key)

# openWrite: encrypt the file before sending it
data = encrypt_payload(data, mode, key)
send_packet(s, "DP", [encode_field(data)])
```

### Explanation

- In the setup phase the client prepares the three keys the assignment lists: the **session key** and its own **RSA public and private keys**.
- The session key is encrypted with the **server's public key**, so only the server can read it, even if the `EC` packet is captured.
- The `EC` packet carries the algorithm, the encrypted session key, and `username:client_public_key`.
- File contents are encrypted with the session key before upload and decrypted after download.

---

## Part 6: Base64 in the C client (`ayham_client.c`)

The C client is unsecured (no encryption), as the assignment requires. It only needs Base64, which is **encoding, not encryption**: our packets carry the filename and file contents in Base64, so commas inside them cannot break the packet format.

### Prompt 

> How do I add openRead to my C client, including Base64 encoding and decoding, using only arrays and pointers?

### Output (generated code, with our comments)

```c
char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Encode: every 3 bytes become 4 Base64 characters */
void base64_encode(char *input, int length, char *output) {
    int i = 0;
    int j = 0;

    while (i < length) {
        unsigned char b1 = input[i];
        unsigned char b2 = 0;
        unsigned char b3 = 0;
        ...
        /* Split the 24 bits into four 6-bit numbers */
        output[j] = base64_chars[b1 >> 2];
        output[j + 1] = base64_chars[((b1 & 3) << 4) | (b2 >> 4)];
        output[j + 2] = base64_chars[((b2 & 15) << 2) | (b3 >> 6)];
        output[j + 3] = base64_chars[b3 & 63];
        /* '=' padding when the last group has fewer than 3 bytes */
        ...
        i = i + 3;
        j = j + 4;
    }
    output[j] = '\0';
}

/* Decode: every 4 Base64 characters become 3 bytes */
int base64_decode(char *input, char *output) {
    ...
    output[j] = (v1 << 2) | (v2 >> 4);
    output[j + 1] = ((v2 & 15) << 4) | (v3 >> 2);
    output[j + 2] = ((v3 & 3) << 6) | v4;
    ...
}

/* openRead: send (CM,openRead,<base64 filename>) */
base64_encode(filename, strlen(filename), encoded_name);
strcpy(request, "(CM,openRead,");
strcat(request, encoded_name);
strcat(request, ")");
send_packet(socket_fd, request);
```

### Explanation

- Base64 uses 64 characters, so each character holds 6 bits. Three bytes (24 bits) become four characters.
- `>>`, `<<`, `&` and `|` cut the bits into 6-bit pieces and join them back.
- `=` at the end is padding when the data length is not a multiple of 3.
- The server's `(DP,...)` reply is decoded with `base64_decode()` and printed. An `(EE,...)` reply's description is decoded the same way.

---

## How we tested the generated code

`test_crypto_utils.py` encrypts and decrypts the session key with RSA, and encrypts and decrypts empty and multi-line content with NONE, AES, and Caesar. All tests passed. We also uploaded and downloaded files between the Python client and the server in NONE, AES and CAESAR modes and got identical files back, and the C client read files from the server correctly, including empty files and files over 4 KB.
