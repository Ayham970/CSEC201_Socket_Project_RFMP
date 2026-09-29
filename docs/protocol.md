# RFMP Protocol Specification

This document is the shared implementation contract for `ayham_server.py`, `ayham_client.py`, and `ayham_client.c`. Both clients must communicate with the same Python server using the rules below.

The assignment defines the packet names and the setup, operation, and closing phases. This document specifies the team's choices for framing, encoding, acknowledgements, limits, and interfaces. It describes intended behavior, not features already implemented or tests already passed.

## 1. Shared settings

| Setting | Value |
| --- | --- |
| Protocol name | `RFMP` |
| Version | `v1.0` |
| Transport | TCP over IPv4 |
| Initial development host | `127.0.0.1` |
| Default port | `5050` |
| Server root | `server_storage/`, resolved from the server script's directory |
| Python client modes | `NONE`, `AES`, `CAESAR` |
| C client mode | `NONE` only |
| File contents | UTF-8 text, transferred as bytes without newline conversion |
| Maximum file contents | 1,048,576 bytes, measured before encryption and Base64 encoding |
| Maximum packet body | 2,097,152 bytes, measured after serialization |
| Requests per connection | One operation at a time; wait for its complete response before starting another |

Each accepted connection has its own session state, working directory, selected mode, session key, client public key, and pending write destination. Multiple connections may operate concurrently.

`NONE` is an internal mode name. An unencrypted connection sends security flag `0` and does not send an `EC` packet.

## 2. Packet framing

TCP is a byte stream. A single `recv()` call may return part of a packet or bytes from more than one packet. Every packet therefore uses the following frame:

| Part | Size | Meaning |
| --- | --- | --- |
| Header | Exactly 4 bytes | Unsigned packet-body length in big-endian network byte order |
| Body | Exactly the length in the header | The serialized packet, including parentheses and commas |

The length excludes the header. No newline or null terminator is appended to the frame.

The sender must send the entire header and body. The receiver must read exactly four header bytes, validate the length, and then read exactly that many body bytes. A valid body length is between 4 and 2,097,152 inclusive. Validate it before allocating a body buffer.

Python uses `struct.pack("!I", length)` and `struct.unpack("!I", header)`. C uses a 32-bit unsigned integer with `htonl()` and `ntohl()`.

Examples of complete body lengths:

| Body text | Body bytes | Four header bytes in hexadecimal |
| --- | ---: | --- |
| `(SS,RFMP,v1.0,0)` | 16 | `00 00 00 10` |
| `(CC)` | 4 | `00 00 00 04` |
| `(CM,openRead,ZXhhbXBsZS50eHQ=)` | 30 | `00 00 00 1e` |
| `(DP,SGVsbG8gUkZNUAo=)` | 21 | `00 00 00 15` |
| `(DP,)` | 5 | `00 00 00 05` |
| `(End)` | 5 | `00 00 00 05` |

The header is binary. For example, `00 00 00 10` means four bytes, not the text string `"00 00 00 10"`.

## 3. Packet syntax and field encoding

The body has the form `(TYPE,field1,field2)`. A packet without fields has the form `(TYPE)`.

- Packet types, subcommands, algorithm names, and version strings are case-sensitive.
- Do not insert spaces around commas or outside the outer parentheses.
- Fixed control fields stay in plain ASCII: packet type, protocol name, version, security flag, algorithm name, command type, and error code.
- Variable content uses standard Base64 with its normal `=` padding and no line wrapping. Do not use URL-safe Base64.
- Text is encoded as UTF-8 before Base64 conversion.
- Key material and file payloads are already bytes and are Base64-encoded directly.
- Decode Base64 strictly. Invalid alphabet characters or padding are protocol errors.
- Preserve empty fields. `(DP,)` is a valid packet with one empty field.
- Parse the envelope and fields before decoding variable content. A decoded filename, command, or file can contain commas without changing the packet structure.

Because variable content is Base64-encoded, the serialized packet body contains only ASCII characters. Base64 is encoding, not encryption.

Throughout this document, `B64(text)` means Base64 of that text's UTF-8 bytes. `B64(bytes)` means Base64 of the supplied bytes. These expressions are explanatory notation and must not be sent literally.

## 4. Packet definitions

| Type | Direction | Body format | Purpose |
| --- | --- | --- | --- |
| `SS` | Client to server | `(SS,RFMP,v1.0,secure)` | Start setup; `secure` is exactly `0` or `1` |
| `CC` | Server to client | `(CC)` | Accept an unencrypted connection |
| `CC` | Server to client | `(CC,server_public_key)` | Supply the public key for encrypted setup |
| `EC` | Client to server | `(EC,algorithm,wrapped_key,username:client_public_key)` | Select encryption and deliver the encrypted session key |
| `CM` | Client to server | `(CM,prompt,command)` | Execute a supported prompt command |
| `CM` | Client to server | `(CM,openRead,filename)` | Read a remote file |
| `CM` | Client to server | `(CM,openWrite,filename)` | Prepare to write a remote file |
| `DP` | Either direction | `(DP,payload)` | Carry file contents, encrypted when selected |
| `SC` | Server to client | `(SC,message)` | Return command output or acknowledge progress/completion |
| `EE` | Server to client | `(EE,code,description)` | Report an error |
| `End` | Client to server | `(End)` | Request connection closure |

The variable fields in this table are encoded as follows:

| Field | Value on the wire |
| --- | --- |
| `server_public_key` | `B64(DER public key bytes)` |
| `algorithm` | Exactly `AES` or `CAESAR` |
| `wrapped_key` | `B64(RSA-encrypted session key bytes)` |
| `username:client_public_key` | `B64(username)` followed by one literal colon and `B64(DER public key bytes)` |
| `command` | `B64(complete command text)` |
| `filename` | `B64(remote relative path)` |
| `payload` | `B64(output of encrypt_payload)` |
| `message` | `B64(acknowledgement text or command output)` |
| `code` | One plain decimal digit from `1` through `4` |
| `description` | `B64(human-readable error description)` |

The colon in the `EC` credentials field is a separator between two independently encoded values. Standard Base64 does not contain colons.

No packet includes extra fields beyond its defined format. Public keys and usernames do not introduce another comma-separated field into `EC`.

## 5. Setup phase

### 5.1 Unencrypted setup

1. The client opens a TCP connection and sends `(SS,RFMP,v1.0,0)`.
2. The server validates the packet and replies `(CC)`.
3. Both sides enter the ready state with mode `NONE` and session key `b""`.

There is no `EC` and no extra setup `SC` in this mode. The C client uses this sequence.

### 5.2 Encrypted setup

1. The client selects `AES` or `CAESAR`, prepares a fresh session key, and generates its RSA key pair.
2. The client opens a TCP connection and sends `(SS,RFMP,v1.0,1)`.
3. The server generates its RSA key pair for this connection and sends `(CC,B64(server_public_key_DER))`.
4. The client loads the server public key and uses it to encrypt the session key.
5. The client sends `EC` with the algorithm, encrypted session key, username, and client public key.
6. The server decrypts the session key with its private key and validates its format for the selected algorithm.
7. The server stores the mode, session key, username, and client public key in this connection's session.
8. The server sends `(SC,B64("SETUP_COMPLETE"))` and enters the ready state.
9. The client waits for that acknowledgement before sending commands.

An invalid handshake receives `EE` when possible, then the server closes the connection. The client must not silently fall back to unencrypted operation.

The assignment contains inconsistent RSA wording and a sentence suggesting `EC` follows `SS` immediately. This implementation follows its illustrated order, `SS`, `CC`, then `EC`, because the client needs the server public key first. RSA encryption uses the recipient's public key; decryption uses the matching private key.

## 6. Encryption conventions

### 6.1 RSA and session keys

- RSA keys have 2048-bit moduli and public exponent 65537.
- Serialize public keys as DER with `SubjectPublicKeyInfo` format, then Base64-encode them for packets.
- Use RSA-OAEP with SHA-256, MGF1 with SHA-256, and label `None`.
- The client encrypts the session key using the server public key. The server decrypts using its private key.
- For `AES`, the session key is exactly 32 random bytes.
- For `CAESAR`, the session key is exactly one byte with numeric value 1 through 25. For shift 3, the key is byte `0x03`, not the ASCII digit `"3"`.
- Generate fresh session keys for each encrypted connection. Never send private keys.
- Parse and retain the client public key as required by the assignment. This protocol does not define a signature or client-authentication exchange.

### 6.2 NONE payload

`encrypt_payload()` and `decrypt_payload()` return their input bytes unchanged. The packet layer still Base64-encodes the payload for transport.

An empty unencrypted file is represented by `(DP,)`.

### 6.3 AES payload

Use `cryptography.hazmat.primitives.ciphers.aead.AESGCM` with the 32-byte session key.

For each outgoing file payload:

1. Generate a fresh 12-byte random nonce. Never reuse a nonce with the same session key, including across directions.
2. Call `AESGCM(session_key).encrypt(nonce, plaintext_bytes, None)`.
3. This returns ciphertext with a 16-byte authentication tag appended.
4. Return the nonce followed by that result from `encrypt_payload()`.
5. Base64-encode the combined bytes into the `DP` field.

The decoded AES payload consists of:

| Component | Length |
| --- | --- |
| Nonce | First 12 bytes |
| Ciphertext | Same length as the original file bytes |
| Authentication tag | Last 16 bytes |

To decrypt, separate the first 12 bytes and pass the remaining bytes to `AESGCM(session_key).decrypt(nonce, ciphertext_and_tag, None)`.

The minimum decoded AES payload is 28 bytes, including for an empty file. A shorter payload or failed tag verification is encryption error `4`. Never save unauthenticated plaintext.

### 6.4 Caesar payload

Apply the shift to byte values for ASCII `A` through `Z` and `a` through `z`, wrapping within the same 26-letter range. Decryption subtracts the shift. Leave every other byte unchanged.

This preserves punctuation, spaces, newlines, and non-ASCII UTF-8 bytes. For shift 3, `Hello, Zz!` becomes `Khoor, Cc!` before Base64 encoding.

An empty Caesar payload is also `(DP,)`.

### 6.5 Scope of encryption

Encryption applies to file contents carried by `DP`. Control packets, commands, filenames, acknowledgements, and errors remain readable after Base64 decoding. Files are stored as their recovered plaintext bytes on the server.

Caesar is an educational cipher. AES authenticates its file payload, but this protocol does not authenticate the server public key or bind all control messages to the encryption session. It must not be described as equivalent to SSH.

## 7. Operation phase

### 7.1 Prompt commands

The client sends `(CM,prompt,B64(command_text))`. The server splits the decoded command using POSIX-style quoting, for example with `shlex.split()`.

| Command | Arguments | Behavior |
| --- | --- | --- |
| `mkdir` | One relative path | Create a directory |
| `cd` | One relative path | Change only this session's directory |
| `rmdir` or `rd` | One relative path | Remove an empty directory |
| `del` | One relative path | Delete a file |
| `ren` | Old relative path and new relative path | Rename a folder |
| `ls` | None | List the current session directory |
| `pwd` | None | Display the session directory relative to the server root, using `/` for the root |
| `whoami` | None | Return the server operating-system username |
| `hostname` | None | Return the server hostname |
| `date` | None | Return the server date and time |

For example, `mkdir "my folder"` is encoded as one command field. `openRead` and `openWrite` are separate `CM` command types and must not be executed through the prompt handler.

On success, send one `SC` containing UTF-8 command output or a meaningful success message. An empty output is permitted as `(SC,)`. On failure, send one `EE` instead. Do not send a `DP` for prompt output.

### 7.2 Read a file

| Step | Sender | Packet or action |
| --- | --- | --- |
| 1 | Client | `(CM,openRead,B64(filename))` |
| 2 | Server | Validate the path, read bytes, and validate UTF-8 content and size |
| 3 | Server | `(DP,B64(encrypt_payload(file_bytes,mode,key)))` |
| 4 | Server | `(SC,B64("READ_COMPLETE"))` |
| 5 | Client | Decode/decrypt the data and consume the completion `SC` before its next request |

Read and encrypt the complete file before sending `DP`. If reading or encryption fails, send only `EE`; do not follow it with `DP` or `SC`.

One complete file uses one `DP`. Framing handles network fragmentation; this version does not define multiple application-level data chunks.

If the client cannot decrypt a received payload or receives an unexpected response, it reports the problem locally and closes the connection. It does not send an `EE`, since `EE` is a server response in this protocol.

### 7.3 Write a file

| Step | Sender | Packet or action |
| --- | --- | --- |
| 1 | Client | Read and validate the local file before requesting a remote write |
| 2 | Client | `(CM,openWrite,B64(filename))` |
| 3 | Server | Validate the destination and remember it as this session's pending write path |
| 4 | Server | `(SC,B64("READY"))` |
| 5 | Client | `(DP,B64(encrypt_payload(file_bytes,mode,key)))` |
| 6 | Server | Decode and decrypt; validate UTF-8 content and plaintext size |
| 7 | Server | Open the destination in binary write mode, write the recovered bytes, and close the file |
| 8 | Server | Clear the pending path and send `(SC,B64("SAVED"))` |

The pending path is a destination record, not an already-truncated file. Do not open or truncate the destination before the data passes validation. Recheck the destination before writing.

Successful writing replaces the contents of an existing file. `openWrite` does not create missing parent directories. Do not use text-mode newline conversion.

If preparing the write fails, send `EE` and remain ready for another command. If processing its `DP` fails, send `EE`, clear the pending path, and return to the ready state. A file-system failure during the actual write must be reported; this basic protocol does not promise rollback of a partially completed disk write.

While waiting for `DP`, accept only that packet or `End`. Any other well-framed packet cancels the pending write, receives error `1`, and returns the session to ready. Do not execute the unexpected command.

### 7.4 Paths and session isolation

- All client-supplied paths are relative to that connection's current directory. Reject absolute paths, empty paths, and embedded null characters.
- Resolve `.` and `..` and check that the resolved path stays inside `server_storage/`. Apply the same containment rule when resolving symlinks.
- `cd ..` is valid only when its result remains inside the server root.
- Keep the session directory in a per-connection variable. Do not use process-wide `os.chdir()` in the multithreaded server.
- When running an external command, supply its working directory explicitly. Execute supported commands through argument lists, not unrestricted shell text.
- A filename in `openRead` or `openWrite` is a complete path field. Do not apply shell splitting or require quotes around spaces in that field.
- This version does not specify coordination of conflicting writes by different clients to the same file. Concurrency demonstrations should use separate destinations unless the implementation adds explicit locking.

## 8. Acknowledgements and errors

### 8.1 SC acknowledgements

The following acknowledgement texts are exact, case-sensitive UTF-8 strings before Base64 encoding:

| Context | Decoded message | Complete packet body |
| --- | --- | --- |
| Encrypted setup finished | `SETUP_COMPLETE` | `(SC,U0VUVVBfQ09NUExFVEU=)` |
| Ready for upload data | `READY` | `(SC,UkVBRFk=)` |
| Upload written successfully | `SAVED` | `(SC,U0FWRUQ=)` |
| Download response complete | `READ_COMPLETE` | `(SC,UkVBRF9DT01QTEVURQ==)` |
| Closing acknowledged | `BYE` | `(SC,QllF)` |

For a prompt command, the message contains its output or success description instead of one of these reserved acknowledgement texts. The client interprets `SC` according to the operation it is currently performing.

### 8.2 EE error codes

Use exactly these four categories. Keep the description specific enough to explain the failure.

| Code | Category | Examples |
| --- | --- | --- |
| `1` | Protocol error | Wrong version, invalid flag, malformed packet, wrong field count, invalid Base64 or text encoding, wrong packet order |
| `2` | File or path error | Missing file, denied access, path outside the root, invalid destination, non-UTF-8 file contents, oversized file, failed file operation |
| `3` | Command error | Unsupported prompt command, wrong argument count, failed external command, command timeout |
| `4` | Encryption error | Unsupported algorithm, invalid RSA key or session-key size, RSA decryption failure, invalid AES payload or authentication tag |

Invalid Base64 syntax is error `1`. Correctly encoded but invalid cryptographic material is error `4`. Text fields such as filenames must decode as UTF-8; invalid file contents are classified separately as error `2`.

Example: `(EE,2,RmlsZSBub3QgZm91bmQ=)` means error `2`, `File not found`.

Never send both `EE` and a success response for the same failed step. A failed read has only `EE`. A failed write after the readiness acknowledgement has `SC READY` followed by `EE`, with no `SC SAVED`.

Clients also handle local socket, allocation, and file errors. Those are local failures, not additional RFMP error codes.

### 8.3 Connection handling after errors

| Situation | Server behavior |
| --- | --- |
| Invalid setup or failed key exchange | Send `EE` if possible, then close |
| Invalid framing, invalid length, or malformed packet body | Send `EE` if possible, then close rather than attempt to resynchronize |
| Well-framed operational error | Send `EE` and keep the session ready |
| Error while awaiting write data | Send `EE`, clear the pending path, and keep the session ready |
| EOF, truncated transmission, or socket failure | Release resources and pending state; do not depend on being able to send a response |

If an outgoing response would exceed the packet limit, return a short appropriate error instead. Never truncate file data silently.

## 9. Closing phase and state rules

After a valid `SS`, the client may request closure with `(End)`, including while encrypted setup or an upload is pending. The server discards pending state, sends `(SC,QllF)`, and closes the connection. The client reads that acknowledgement and closes its socket. The server accepts no more requests on that connection.

A TCP disconnect without `End` is an unexpected disconnection. Clean up that client's resources and continue serving other clients.

| Current state | Accepted packet | Result |
| --- | --- | --- |
| `WAIT_START` | Valid `SS` with flag `0` | Send `CC`; enter `READY` |
| `WAIT_START` | Valid `SS` with flag `1` | Send `CC` with public key; enter `WAIT_EC` |
| `WAIT_EC` | Valid `EC` | Establish encryption; send `SC SETUP_COMPLETE`; enter `READY` |
| `READY` | `CM prompt` | Send `SC` or `EE`; remain `READY` |
| `READY` | `CM openRead` | Send `DP` then `SC`, or only `EE`; remain `READY` |
| `READY` | Valid `CM openWrite` | Send `SC READY`; enter `WAIT_DATA` |
| `WAIT_DATA` | `DP` | Save or report failure; clear pending path; enter `READY` |
| Any state after a valid `SS` | `End` | Send `SC BYE`; enter `CLOSED` |
| Any open state | Connection lost | Clean up; enter `CLOSED` |

`End` before a valid `SS` is an invalid setup packet. Other state violations follow the error rules above. Repeated `SS` or `EC` packets do not renegotiate an established connection.

## 10. Shared Python interfaces

### 10.1 packets.py

| Function | Contract |
| --- | --- |
| `recv_exact(sock, byte_count) -> bytes` | Return exactly the requested bytes; return `b""` for a zero count; raise `EOFError` on socket EOF before completion |
| `send_packet(sock, packet_type, fields) -> None` | Take a packet-type string and a list of prepared field strings; validate and frame them; send all bytes |
| `receive_packet(sock) -> tuple[str, list[str]]` | Receive one frame, validate envelope/type/field count, and return the type plus fields in wire form |
| `encode_field(data: bytes) -> str` | Return standard Base64 text without line breaks |
| `decode_field(text: str) -> bytes` | Strictly decode standard Base64 |

Define `ProtocolError` in `packets.py` for invalid received framing, envelope syntax, field counts, and Base64. Local misuse of `send_packet()` can raise `ValueError`. Socket errors propagate to the connection handler.

`receive_packet()` does not automatically decrypt or Base64-decode its returned fields. The application decodes the fields required by that packet schema and validates their semantic values. Packet helpers never send `EE` by themselves; the server handler selects the appropriate response and state transition.

Example call for a read request:

```python
send_packet(sock, "CM", ["openRead", encode_field("example.txt".encode("utf-8"))])
```

Encoding happens once. For a file upload, call `encrypt_payload()` first and `encode_field()` on its returned bytes. At the receiver, call `decode_field()` first and `decrypt_payload()` on the decoded bytes.

### 10.2 crypto_utils.py

| Function | Contract |
| --- | --- |
| `generate_rsa_keypair()` | Return `(private_key, public_key)` in that order |
| `serialize_public_key(public_key) -> bytes` | Return DER SubjectPublicKeyInfo bytes, without Base64 |
| `load_public_key(serialized_key: bytes)` | Load and validate the agreed RSA public-key type and parameters |
| `generate_session_key(mode: str) -> bytes` | Return `b""` for `NONE`, 32 random bytes for `AES`, or one shift byte for `CAESAR` |
| `encrypt_session_key(server_public_key, session_key: bytes) -> bytes` | Return RSA-OAEP ciphertext |
| `decrypt_session_key(server_private_key, encrypted_key: bytes) -> bytes` | Return the recovered session-key bytes |
| `encrypt_payload(data: bytes, mode: str, session_key: bytes) -> bytes` | Return the agreed raw payload for the selected mode, without Base64 |
| `decrypt_payload(data: bytes, mode: str, session_key: bytes) -> bytes` | Return the original file bytes or raise a validation/decryption exception |

Encryption helpers contain no socket operations, user prompts, or file writes. Handlers convert their failures to error `4` where appropriate. Unknown modes are rejected; they never behave like `NONE`.

## 11. Complete unencrypted example

Every body below has its own four-byte length header. The example file is `example.txt` and its exact contents are `Hello RFMP` followed by one LF newline, for a total of 11 bytes.

| Step | Direction | Exact body |
| --- | --- | --- |
| Start | Client to server | `(SS,RFMP,v1.0,0)` |
| Accept | Server to client | `(CC)` |
| Prepare upload | Client to server | `(CM,openWrite,ZXhhbXBsZS50eHQ=)` |
| Ready | Server to client | `(SC,UkVBRFk=)` |
| Upload data | Client to server | `(DP,SGVsbG8gUkZNUAo=)` |
| Saved | Server to client | `(SC,U0FWRUQ=)` |
| Request download | Client to server | `(CM,openRead,ZXhhbXBsZS50eHQ=)` |
| Download data | Server to client | `(DP,SGVsbG8gUkZNUAo=)` |
| Read complete | Server to client | `(SC,UkVBRF9DT01QTEVURQ==)` |
| End | Client to server | `(End)` |
| Goodbye | Server to client | `(SC,QllF)` |

The C client performs the start, accept, request-download, download-data, read-complete, end, and goodbye steps. It does not upload, run prompt commands, or negotiate encryption.

In C, preserve the empty field in `(DP,)`, handle partial sends and receives, and use explicit byte lengths when displaying recovered contents. A local buffer's null terminator is not part of the network frame or file contents.

## 12. Implementation acceptance checklist

These are tests to perform, not results already obtained.

- [ ] Python and C complete unencrypted setup against the same server.
- [ ] `SS` with flag `0` produces only `CC`; neither side waits for `EC` or an extra setup acknowledgement.
- [ ] Encrypted setup follows `SS`, `CC`, `EC`, `SC SETUP_COMPLETE`.
- [ ] Framing works when headers or bodies are split across sends and when multiple frames arrive together.
- [ ] Empty files, commas, newlines, spaces in filenames, and non-ASCII UTF-8 text are preserved.
- [ ] A file larger than 4 KB arrives in full.
- [ ] A file over 1 MiB is rejected with a clear error.
- [ ] Python write/read round trips recover identical bytes in all three modes.
- [ ] Each read consumes both `DP` and `SC READ_COMPLETE` before the next request.
- [ ] Each write waits for `SC READY`, then consumes `SC SAVED` or `EE` after `DP`.
- [ ] Invalid AES data is rejected before opening or changing the destination file.
- [ ] Missing files, unsupported commands, malformed packets, and wrong state transitions produce the agreed errors.
- [ ] Two clients maintain independent working directories and encryption state.
- [ ] A client's normal or unexpected closure does not stop the server.
- [ ] The C client reads both normal and empty files and handles `EE`.

## 13. Implementation references

- [Python Socket Programming HOWTO](https://docs.python.org/3/howto/sockets.html)
- [Cryptography RSA documentation](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/rsa/)
- [Cryptography AESGCM documentation](https://cryptography.io/en/stable/hazmat/primitives/aead/)

The packet serialization, size limits, acknowledgement texts, and state conventions in this document are team design decisions. Confirm any instructor-specific formatting expectations before changing them, and update this document whenever the group agrees on a protocol change.
