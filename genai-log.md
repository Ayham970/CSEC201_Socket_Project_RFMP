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
