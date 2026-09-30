
# ayham_client.py - RFMP Python client

import socket
from packets import send_packet, receive_packet, encode_field, decode_field

host = "127.0.0.1"
port = 5050
max_file_size = 1048576  # 1 MiB


# Receive a reply and display any error sent by the server.
def get_reply(expected_type, field_count):
    packet_type, fields = receive_packet(s)
    if packet_type == "EE":
        if len(fields) != 2 or fields[0] not in ("1", "2", "3", "4"):
            raise ValueError("Invalid error packet")
        print("Server error " + fields[0] + ": " + decode_field(fields[1]).decode("utf-8"))
        return None
    if packet_type != expected_type or len(fields) != field_count:
        raise ValueError("Unexpected server reply")
    return fields


# Check that the server has finished the current step.
def get_message(expected_message):
    fields = get_reply("SC", 1)
    if fields is None:
        return False
    message = decode_field(fields[0]).decode("utf-8")
    if message != expected_message:
        raise ValueError("Expected " + expected_message + ", received " + message)
    return True


# Create a TCP socket, like the example from class.
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(30)

try:
    mode = input("Choose NONE, AES or CAESAR: ").strip().upper()
    while mode not in ("NONE", "AES", "CAESAR"):
        mode = input("Please enter NONE, AES or CAESAR: ").strip().upper()

    key = b""
    if mode != "NONE":
        from crypto_utils import generate_rsa_keypair, serialize_public_key
        from crypto_utils import load_public_key, generate_session_key, encrypt_session_key
        from crypto_utils import encrypt_payload, decrypt_payload

        username = input("Username: ")
        private_key, public_key = generate_rsa_keypair()
        key = generate_session_key(mode)

    s.connect((host, port))

    # Setup phase: start the session and wait for the server.
    if mode == "NONE":
        send_packet(s, "SS", ["RFMP", "v1.0", "0"])
        if get_reply("CC", 0) is None:
            raise ValueError("Connection refused")
    else:
        send_packet(s, "SS", ["RFMP", "v1.0", "1"])
        fields = get_reply("CC", 1)
        if fields is None:
            raise ValueError("Encrypted connection refused")
        server_key = load_public_key(decode_field(fields[0]))
        wrapped_key = encrypt_session_key(server_key, key)
        credentials = encode_field(username.encode("utf-8")) + ":" + encode_field(serialize_public_key(public_key))
        send_packet(s, "EC", [mode, encode_field(wrapped_key), credentials])
        if not get_message("SETUP_COMPLETE"):
            raise ValueError("Encryption setup failed")

    print("Connected to the server.")

    # Operation phase: handle one request at a time.
    while True:
        print("\n1. Run a command\n2. Read a file\n3. Write a file\n4. End")
        try:
            choice = input("Choose 1-4: ").strip()
        except (EOFError, KeyboardInterrupt):
            choice = "4"

        if choice == "1":
            print("Commands: mkdir, cd, rmdir, rd, del, ren, ls, pwd, whoami, hostname, date")
            command = input("Command: ")
            send_packet(s, "CM", ["prompt", encode_field(command.encode("utf-8"))])
            fields = get_reply("SC", 1)
            if fields is not None:
                print(decode_field(fields[0]).decode("utf-8"))

        elif choice == "2":
            filename = input("Remote filename (relative path): ")
            local_name = input("Save locally as (existing file will be replaced): ")
            send_packet(s, "CM", ["openRead", encode_field(filename.encode("utf-8"))])
            fields = get_reply("DP", 1)
            if fields is None:
                continue
            data = decode_field(fields[0])
            if mode != "NONE":
                data = decrypt_payload(data, mode, key)
            if len(data) > max_file_size:
                raise ValueError("Downloaded file exceeds 1 MiB")
            data.decode("utf-8")  # Check that this is a UTF-8 text file.
            if not get_message("READ_COMPLETE"):
                raise ValueError("Download did not finish correctly")
            # Save only after the data and completion reply are valid.
            try:
                with open(local_name, "wb") as file:
                    file.write(data)
                print("File downloaded.")
            except OSError as error:
                print("Cannot save local file:", error)

        elif choice == "3":
            local_name = input("Local filename: ")
            filename = input("Remote filename (existing file will be replaced): ")
            # Read and check the local file before asking the server to write.
            try:
                with open(local_name, "rb") as file:
                    data = file.read(max_file_size + 1)
                if len(data) > max_file_size:
                    raise ValueError("File exceeds 1 MiB")
                data.decode("utf-8")
            except (OSError, ValueError) as error:
                print("Cannot upload file:", error)
                continue
            if mode != "NONE":
                data = encrypt_payload(data, mode, key)
            payload = encode_field(data)
            send_packet(s, "CM", ["openWrite", encode_field(filename.encode("utf-8"))])
            if not get_message("READY"):
                continue
            send_packet(s, "DP", [payload])
            if get_message("SAVED"):
                print("File uploaded.")

        elif choice == "4":
            # Closing phase: tell the server, receive BYE, then close.
            send_packet(s, "End", [])
            if get_message("BYE"):
                print("Goodbye.")
            break

        else:
            print("Please choose 1, 2, 3 or 4.")

except (EOFError, KeyboardInterrupt):
    print("\nClient stopped.")
except Exception as error:
    print("Error:", error)
finally:
    s.close()
