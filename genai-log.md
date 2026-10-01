# Generative AI Usage Log

## Task Completed

I used ChatGPT to help implement the shared RFMP packet-framing and field-encoding functions in `packets.py`. I also used it to implement the initial `NONE` pass-through functions in `crypto_utils.py` and create `requirements.txt`.

## Prompt

Implement packet framing, complete sending and receiving, and Base64 helpers in `packets.py`. Create `crypto_utils.py` with working `NONE` pass-through functions. Add `requirements.txt`. Use the shared protocol specification and include detailed comments.

## AI-Assisted Output

The AI helped implement and explain:

- A four-byte, big-endian packet-length header.
- `recv_exact()` to handle partial TCP receives.
- `send_packet()` to create and transmit a complete framed packet.
- `receive_packet()` to receive and validate one complete packet.
- `encode_field()` and `decode_field()` for strict standard Base64.
- Packet-type and field-count validation.
- `generate_session_key()` for `NONE` mode.
- `encrypt_payload()` and `decrypt_payload()` as `NONE` pass-through functions.
- A `requirements.txt` file explaining the current dependencies.

## Testing Performed

The Base64 functions were tested using the text `Hello`.

Expected and received output:

```text
SGVsbG8=
b'Hello'
```

Packet sending and receiving were tested using two locally connected sockets. The test successfully sent and received:

```text
(SS,RFMP,v1.0,0)
```

The `NONE` encryption functions were tested using the payload `Hello RFMP`.

Expected and received output:

```text
b''
b'Hello RFMP'
b'Hello RFMP'
```

## My Understanding

TCP transfers a stream of bytes and does not preserve packet boundaries. The four-byte header states the exact length of the following packet body. `recv_exact()` repeatedly calls `recv()` until it collects the required number of bytes.

Base64 converts variable binary or text data into safe ASCII characters so commas and parentheses inside the original data cannot break the packet structure. Base64 does not encrypt information.

In `NONE` mode, no encryption key is needed. The session key is `b""`, and encryption and decryption return the original bytes unchanged.

---

# Person 1 (Ayham): Python Server (`ayham_server.py`)

## Tool Used

Claude (Anthropic), used as a coding assistant from September 29 to October 1.

## How I Used It

I gave Claude the assignment sheet, our `docs/protocol.md`, our daily work plan, and the lecture slides (`Python Sockets.pdf`, `Python Threading.pdf`). I asked it to write and test the server one day at a time, following the plan. I reviewed each version, asked it to change parts I did not understand or had not learned in class, and asked it to explain the final code line by line.

## Prompts

### September 29: Basic server

> "Change the server based on the requirement but keep it for day 1 only: create the listening server, client handler, and separate session record for each connection. Receive unencrypted SS, send CC, and handle End. I am Person 1."

> "This is how we made our code for sockets [lecture slides attached], in my code I used shortcuts, fix it."

> "Make it simple, don't use advanced stuff."

### September 30: File transfers and commands

> "Implement openRead and openWrite, including the agreed acknowledgements. Add mkdir, cd, ls, and pwd. Keep each client's working directory separate."

> "What is shlex?" followed by "Don't use it, we have not taken it."

### October 1: Secured setup and remaining commands

> "Let's do my part for today: implement secured setup (send the server public key, receive EC, recover the session key, and keep it in the client's session). Integrate encryption into reads and writes. Finish rmdir/rd, del, ren, whoami, hostname, and date."

> "Isn't secured_setup() supposed to be in Elie's part?"

> "Explain to me my server code in detail."

## AI-Assisted Output

Claude wrote the following parts of `ayham_server.py`:

- **Server socket and threads.** `socket()`, `bind()`, `listen(5)`, `accept()`, and one `threading.Thread` per client, rewritten to match the style of the lecture slides.
- **Session record.** A `session` dictionary created inside `handle_client()`, so every client has its own state, current directory, mode, session key, username, and pending upload path.
- **Setup and closing phases.** Validation of `(SS,RFMP,v1.0,0|1)`, the `(CC)` reply, and `End` answered with `(SC,BYE)`.
- **`resolve_path()`.** Keeps every client path inside `server_storage/` and rejects `..`, absolute paths, and symlinks that escape the root.
- **Prompt commands.** `mkdir`, `cd`, `ls`, `pwd`, `rmdir`/`rd`, `del`, `ren`, `whoami`, `hostname`, and `date`, kept in a `COMMANDS` table. `whoami` and `hostname` use `subprocess.run()`.
- **openRead.** Sends `(DP,data)` followed by `(SC,READ_COMPLETE)`, or only `EE` on failure.
- **openWrite.** A two-step exchange, `(SC,READY)` then `DP` then `(SC,SAVED)`. The file is opened only after the data has been decrypted and checked.
- **`secured_setup()`.** Generates an RSA key pair for each client, sends `(CC,public_key)`, receives `EC`, decrypts the session key with the server private key, checks the key size (AES 32 bytes, Caesar shift 1 to 25), and stores it in the session.
- **Error handling.** `EE` packets using our four error codes, and `try/except/finally` so one client's error or disconnection never stops the server.

## Changes I Asked For

- Removed helper functions and shortcuts so the socket code matches the lecture slides.
- Removed `shlex` (not covered in class) and used `.split()` instead. File and folder names therefore cannot contain spaces.
- Removed `setsockopt(SO_REUSEADDR)` because it is not in the slides.
- Kept the encryption math in Elie's `crypto_utils.py`. The server only calls those functions.

## Testing Performed

Claude ran the server with our real `ayham_client.py` and with extra test scripts. Results:

- SS, CC, and End worked for both unsecured and secured clients.
- Upload followed by download returned identical bytes in NONE, AES, and CAESAR modes, and files were stored on the server as plaintext.
- All 11 prompt commands worked. Wrong arguments returned `EE 3`.
- Two clients at the same time kept separate directories and separate keys (one AES, one CAESAR).
- Altered AES data was rejected with `EE 4` and no file was written.
- An invalid algorithm, wrong key size, bad public key, or wrong packet order during setup returned `EE 1` or `EE 4`.
- `cd ../..`, `del ../../etc/passwd`, and `rmdir .` were blocked.
- Split packets, garbage packets, and clients disconnecting without `End` did not crash the server.

Note: the secured tests used a temporary `crypto_utils.py` that follows `protocol.md` section 10.2, because Elie's RSA, AES, and Caesar functions were not in the repository yet. They must be retested with Elie's version.

## My Understanding

- **Threads.** `recv()` blocks while waiting for data. Without a thread per client, one slow client would freeze every other client.
- **Session dictionary.** It is created inside `handle_client()`, so each thread has its own copy. This is why `cd` changes `session["current_directory"]` and never calls `os.chdir()`, which would change the directory for every thread at once.
- **`resolve_path()`.** `os.path.realpath()` resolves `..` and symlinks to the real location. If that location is not inside `server_storage/`, the request is refused.
- **openWrite in two steps.** Opening a file with `"wb"` erases it. The server waits until the uploaded data has been decrypted and validated before opening the file, so a failed upload cannot destroy an existing file.
- **RSA and session key.** RSA is slow and only suitable for small data, so it is used only to send the AES or Caesar key safely. The client encrypts the key with the server public key, and only the server private key can decrypt it. The faster AES or Caesar cipher then encrypts file contents.
- **Error codes.** 1 = protocol error, 2 = file or path error, 3 = command error, 4 = encryption error.
