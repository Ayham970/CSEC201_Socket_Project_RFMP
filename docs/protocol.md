# RFMP Protocol Specification

Remote File Management Protocol (RFMP) v1.0, used by `ayham_server.py`, `ayham_client.py`, and `ayham_client.c`.

## 1. Settings

| Setting | Value |
| --- | --- |
| Protocol / version | `RFMP` / `v1.0` |
| Transport | TCP, port `5050` |
| Server folder | `server_storage/` (next to the server script) |
| Python client modes | `NONE`, `AES`, `CAESAR` |
| C client | `NONE` only, `openRead` only |

The server runs one thread per client. Each client has its own session: current directory, mode, and session key.

## 2. Packet format

A packet is text in the form `(TYPE,field1,field2)`, or `(TYPE)` with no fields.

- **Framing.** Before each packet, the sender sends its length as a 4-byte big-endian number (`struct.pack("!I", length)` in Python, `htonl()` in C). The receiver reads the 4 bytes, then exactly that many bytes.
- **Base64.** Filenames, commands, file data, keys, and messages are Base64-encoded, so commas inside them cannot break the packet. Base64 is encoding, not encryption.

## 3. Packets

| Type | Direction | Format |
| --- | --- | --- |
| `SS` | Client → Server | `(SS,RFMP,v1.0,0)` unsecured, `(SS,RFMP,v1.0,1)` secured |
| `CC` | Server → Client | `(CC)` unsecured, `(CC,server_public_key)` secured |
| `EC` | Client → Server | `(EC,algorithm,encrypted_session_key,username:client_public_key)` |
| `CM` | Client → Server | `(CM,prompt,command)`, `(CM,openRead,filename)`, `(CM,openWrite,filename)` |
| `DP` | Both | `(DP,file_data)` |
| `SC` | Server → Client | `(SC,message)` |
| `EE` | Server → Client | `(EE,code,description)` |
| `End` | Client → Server | `(End)` |

`algorithm` is `AES` or `CAESAR`. Error codes are plain digits; all other variable fields are Base64.

## 4. Setup phase

**Unsecured:**
```
Client: (SS,RFMP,v1.0,0)
Server: (CC)
```

**Secured:**
```
Client: (SS,RFMP,v1.0,1)
Server: (CC,server_public_key)
Client: (EC,AES or CAESAR,encrypted_session_key,username:client_public_key)
Server: (SC,SETUP_COMPLETE)
```

1. The client chooses AES or CAESAR, creates a session key, and creates its RSA key pair.
2. The server creates its RSA key pair and sends its public key in `CC`.
3. The client encrypts the session key with the server's public key and sends `EC`.
4. The server decrypts the session key with its private key and stores it in the client's session.

## 5. Encryption

| Algorithm | Used for | Details |
| --- | --- | --- |
| RSA | Session key | 2048-bit keys, OAEP with SHA-256. Public keys are sent in DER format. |
| AES | File data | AES-GCM, 32-byte key. Payload = 12-byte nonce + ciphertext + 16-byte tag. |
| Caesar | File data | 1-byte key, shift 1 to 25. Only letters A-Z and a-z are shifted. |

Only file data in `DP` packets is encrypted. The server saves files as plaintext.

## 6. Operation phase

### Prompt commands

`(CM,prompt,command)` → `(SC,output)` or `(EE,...)`

The server splits the command on spaces, so file and folder names cannot contain spaces.

| Command | Action |
| --- | --- |
| `mkdir name` | Create a folder |
| `cd name` | Change this client's directory |
| `rmdir name` / `rd name` | Delete an empty folder |
| `del name` | Delete a file |
| `ren old new` | Rename a folder |
| `ls` | List the current directory |
| `pwd` | Show the current directory |
| `whoami` | Server username |
| `hostname` | Server computer name |
| `date` | Server date and time |

### openRead

```
Client: (CM,openRead,filename)
Server: (DP,file_data)
Server: (SC,READ_COMPLETE)
```
On error the server sends only `(EE,...)`.

### openWrite

```
Client: (CM,openWrite,filename)
Server: (SC,READY)
Client: (DP,file_data)
Server: (SC,SAVED)
```
On error the server sends `(EE,...)` instead of `READY` or `SAVED`.

In secured mode, `file_data` is encrypted with the session key before sending and decrypted after receiving.

## 7. Closing phase

```
Client: (End)
Server: (SC,BYE)
```
Both sides then close the connection.

## 8. Error codes

| Code | Meaning | Examples |
| --- | --- | --- |
| `1` | Protocol error | Wrong packet, wrong version, bad format |
| `2` | File or folder error | File not found, folder already exists, path outside `server_storage/` |
| `3` | Command error | Unknown command, wrong number of arguments |
| `4` | Encryption error | Unknown algorithm, bad key, decryption failed |

Example: `(EE,2,RmlsZSBub3QgZm91bmQ=)` means error 2, "File not found".

## 9. Shared Python files

**`packets.py`**: `send_packet(sock, type, fields)`, `receive_packet(sock)`, `encode_field(bytes)`, `decode_field(text)`

**`crypto_utils.py`**: `generate_rsa_keypair()`, `serialize_public_key()`, `load_public_key()`, `generate_session_key(mode)`, `encrypt_session_key()`, `decrypt_session_key()`, `encrypt_payload(data, mode, key)`, `decrypt_payload(data, mode, key)`
