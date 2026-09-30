# ayham_server.py
# RFMP Server 
# Sep 29: listening server, one thread per client, separate session record,
#        unencrypted SS -> CC, and End.
# Sep 30: openRead, openWrite, and the prompt commands mkdir, cd, ls, pwd.
#        Each client keeps its own working directory.
# Uses Person 3's packets.py (framing + Base64) and crypto_utils.py.

import socket
import threading
import os

from packets import send_packet, receive_packet, encode_field, decode_field, ProtocolError
from crypto_utils import encrypt_payload, decrypt_payload

HOST = "127.0.0.1"
PORT = 5050

PROTOCOL_NAME = "RFMP"
PROTOCOL_VERSION = "v1.0"

# Largest file we accept or send (protocol.md section 1): 1 MiB
MAX_FILE_SIZE = 1048576

# server_storage/ is next to this script (protocol.md section 1)
SERVER_ROOT = os.path.realpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "server_storage")
)

# Error codes (protocol.md section 8.2)
# 1 = protocol error
# 2 = file or path error
# 3 = command error
# 4 = encryption error


def send_error(clientsocket, code, description):
    # EE packet: (EE,code,B64(description))
    send_packet(clientsocket, "EE", [str(code), encode_field(description.encode("utf-8"))])


def send_success(clientsocket, message):
    # SC packet: (SC,B64(message))
    send_packet(clientsocket, "SC", [encode_field(message.encode("utf-8"))])


def resolve_path(session, relative_path):
    # Turn a client path into a full path inside server_storage/.
    # Returns None if the path is not allowed.

    # Reject empty paths, absolute paths, and null characters
    if relative_path == "" or "\0" in relative_path:
        return None
    if os.path.isabs(relative_path):
        return None

    # Join with THIS client's current directory, then clean up . and ..
    # realpath also follows symlinks so they can't escape the root.
    full_path = os.path.realpath(os.path.join(session["current_directory"], relative_path))

    # The result must still be inside the server root
    if full_path != SERVER_ROOT and not full_path.startswith(SERVER_ROOT + os.sep):
        return None

    return full_path


# ---------- PROMPT COMMANDS ----------
# Each one returns (True, output) on success or (False, error message).
# We do NOT use os.chdir() because it would change the directory
# for every thread. Each client's directory is kept in its session.

def cmd_mkdir(session, args):
    if len(args) != 1:
        return False, "Usage: mkdir <folder>"
    path = resolve_path(session, args[0])
    if path is None:
        return False, "Path is outside the server folder"
    os.mkdir(path)
    return True, "Folder created: " + args[0]


def cmd_cd(session, args):
    if len(args) != 1:
        return False, "Usage: cd <folder>"
    path = resolve_path(session, args[0])
    if path is None:
        return False, "Path is outside the server folder"
    if not os.path.isdir(path):
        return False, "Folder not found: " + args[0]
    session["current_directory"] = path
    return cmd_pwd(session, [])


def cmd_ls(session, args):
    if len(args) != 0:
        return False, "Usage: ls"
    names = sorted(os.listdir(session["current_directory"]))
    lines = []
    for name in names:
        # Put a / after folder names so the user can tell them apart
        if os.path.isdir(os.path.join(session["current_directory"], name)):
            lines.append(name + "/")
        else:
            lines.append(name)
    return True, "\n".join(lines)


def cmd_pwd(session, args):
    if len(args) != 0:
        return False, "Usage: pwd"
    # Show the path relative to the server root, "/" for the root itself
    relative = os.path.relpath(session["current_directory"], SERVER_ROOT)
    if relative == ".":
        return True, "/"
    return True, "/" + relative.replace(os.sep, "/")


# Table of supported prompt commands
COMMANDS = {
    "mkdir": cmd_mkdir,
    "cd": cmd_cd,
    "ls": cmd_ls,
    "pwd": cmd_pwd,
}


def handle_prompt(clientsocket, session, command_field):
    # (CM,prompt,B64(command)) -> one SC or one EE
    command_text = decode_field(command_field).decode("utf-8")

    # Split the command into words at spaces: "mkdir test" -> ["mkdir", "test"]
    # (folder and file names cannot contain spaces)
    words = command_text.split()

    if len(words) == 0:
        send_error(clientsocket, 3, "Empty command")
        return

    name = words[0]
    args = words[1:]

    if name not in COMMANDS:
        send_error(clientsocket, 3, "Unsupported command: " + name)
        return

    try:
        ok, output = COMMANDS[name](session, args)
    except FileExistsError:
        send_error(clientsocket, 2, "Already exists: " + args[0])
        return
    except FileNotFoundError:
        send_error(clientsocket, 2, "Path not found")
        return
    except PermissionError:
        send_error(clientsocket, 2, "Permission denied")
        return
    except OSError as e:
        send_error(clientsocket, 2, "File operation failed: " + str(e))
        return

    if ok:
        send_success(clientsocket, output)
    elif output.startswith("Usage"):
        send_error(clientsocket, 3, output)       # wrong number of arguments
    else:
        send_error(clientsocket, 2, output)       # bad path


# ---------- openRead ----------
def handle_open_read(clientsocket, session, filename_field):
    # Success: (DP,B64(file)) then (SC,B64("READ_COMPLETE"))
    # Failure: only (EE,...)
    filename = decode_field(filename_field).decode("utf-8")

    path = resolve_path(session, filename)
    if path is None:
        send_error(clientsocket, 2, "Path is outside the server folder")
        return
    if not os.path.isfile(path):
        send_error(clientsocket, 2, "File not found: " + filename)
        return
    if os.path.getsize(path) > MAX_FILE_SIZE:
        send_error(clientsocket, 2, "File is larger than 1 MiB")
        return

    # Read the whole file as bytes (binary mode = no newline changes)
    try:
        file = open(path, "rb")
        data = file.read()
        file.close()
    except OSError as e:
        send_error(clientsocket, 2, "Cannot read file: " + str(e))
        return

    # Only UTF-8 text files are allowed
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        send_error(clientsocket, 2, "File is not UTF-8 text")
        return

    # Encrypt (NONE mode returns the same bytes), then send
    try:
        payload = encrypt_payload(data, session["mode"], session["session_key"])
    except Exception as e:
        send_error(clientsocket, 4, "Encryption failed: " + str(e))
        return

    send_packet(clientsocket, "DP", [encode_field(payload)])
    send_success(clientsocket, "READ_COMPLETE")


# ---------- openWrite (step 1) ----------
def handle_open_write(clientsocket, session, filename_field):
    # Check the destination and remember it. Do NOT open the file yet.
    filename = decode_field(filename_field).decode("utf-8")

    path = resolve_path(session, filename)
    if path is None:
        send_error(clientsocket, 2, "Path is outside the server folder")
        return
    if os.path.isdir(path):
        send_error(clientsocket, 2, "Destination is a folder: " + filename)
        return
    if not os.path.isdir(os.path.dirname(path)):
        send_error(clientsocket, 2, "Parent folder does not exist")
        return

    session["pending_write_path"] = path
    session["state"] = "WAIT_DATA"
    send_success(clientsocket, "READY")


# ---------- openWrite (step 2): the DP packet ----------
def handle_write_data(clientsocket, session, payload_field):
    # Whatever happens, go back to READY and forget the pending path
    path = session["pending_write_path"]
    session["pending_write_path"] = None
    session["state"] = "READY"

    payload = decode_field(payload_field)

    try:
        data = decrypt_payload(payload, session["mode"], session["session_key"])
    except Exception as e:
        send_error(clientsocket, 4, "Decryption failed: " + str(e))
        return

    if len(data) > MAX_FILE_SIZE:
        send_error(clientsocket, 2, "File is larger than 1 MiB")
        return

    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        send_error(clientsocket, 2, "File is not UTF-8 text")
        return

    # Check again before writing: the path must not have become a
    # symlink or a folder since openWrite
    if os.path.realpath(path) != path or os.path.isdir(path):
        send_error(clientsocket, 2, "Destination is no longer valid")
        return

    # Write in binary mode so newlines are saved exactly
    try:
        file = open(path, "wb")
        file.write(data)
        file.close()
    except OSError as e:
        send_error(clientsocket, 2, "Cannot write file: " + str(e))
        return

    send_success(clientsocket, "SAVED")


def handle_client(clientsocket, addr):
    print("Got a connection from %s" % str(addr))

    # Separate session record for this client only
    session = {
        "state": "WAIT_START",
        "current_directory": SERVER_ROOT,
        "mode": "NONE",
        "session_key": b"",
        "username": None,
        "client_public_key": None,
        "pending_write_path": None,
    }

    try:
        # ---------- SETUP PHASE ----------
        # Expected: (SS,RFMP,v1.0,0)
        packet_type, fields = receive_packet(clientsocket)

        if packet_type != "SS" or len(fields) != 3:
            send_error(clientsocket, 1, "Expected SS packet")
            return

        protocol_name = fields[0]
        version = fields[1]
        secure = fields[2]

        if protocol_name != PROTOCOL_NAME or version != PROTOCOL_VERSION:
            send_error(clientsocket, 1, "Wrong protocol name or version")
            return

        if secure == "1":
            # Encrypted setup is added on Day 3
            send_error(clientsocket, 4, "Encrypted setup not implemented yet")
            return

        if secure != "0":
            send_error(clientsocket, 1, "Security flag must be 0 or 1")
            return

        # Not secured: reply (CC)
        send_packet(clientsocket, "CC", [])
        session["state"] = "READY"
        print("Handshake done with %s" % str(addr))

        # ---------- OPERATION PHASE ----------
        while session["state"] in ("READY", "WAIT_DATA"):
            packet_type, fields = receive_packet(clientsocket)

            # ---------- CLOSING PHASE ----------
            # End is allowed in READY and WAIT_DATA
            if packet_type == "End":
                session["pending_write_path"] = None
                send_success(clientsocket, "BYE")
                break

            try:
                # Waiting for upload data: only DP (or End above) is allowed
                if session["state"] == "WAIT_DATA":
                    if packet_type == "DP":
                        handle_write_data(clientsocket, session, fields[0])
                    else:
                        session["pending_write_path"] = None
                        session["state"] = "READY"
                        send_error(clientsocket, 1, "Expected DP; upload cancelled")

                elif packet_type == "CM":
                    command_type = fields[0]
                    if command_type == "prompt":
                        handle_prompt(clientsocket, session, fields[1])
                    elif command_type == "openRead":
                        handle_open_read(clientsocket, session, fields[1])
                    elif command_type == "openWrite":
                        handle_open_write(clientsocket, session, fields[1])
                    else:
                        send_error(clientsocket, 1, "Unknown command type: " + command_type)

                else:
                    send_error(clientsocket, 1, "Expected CM or End")

            except (ProtocolError, UnicodeDecodeError):
                # Bad Base64 or bad UTF-8 inside a well-framed packet:
                # report it and keep the session open
                session["pending_write_path"] = None
                session["state"] = "READY"
                send_error(clientsocket, 1, "Invalid field encoding")

    except ProtocolError as e:
        # Bad framing or malformed packet: send EE if possible, then close
        try:
            send_error(clientsocket, 1, str(e))
        except OSError:
            pass

    except EOFError:
        print("Client disconnected without End: %s" % str(addr))

    except OSError as e:
        print("Connection error with %s: %s" % (str(addr), e))

    finally:
        session["state"] = "CLOSED"
        session["pending_write_path"] = None
        clientsocket.close()
        print("Connection closed: %s" % str(addr))


# Make sure the storage folder exists
if not os.path.exists(SERVER_ROOT):
    os.mkdir(SERVER_ROOT)

# create a socket object
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# bind to the port
serversocket.bind((HOST, PORT))

# queue up to 5 requests
serversocket.listen(5)
print("RFMP server listening on %s:%d" % (HOST, PORT))

while True:
    # establish a connection
    clientsocket, addr = serversocket.accept()

    # new thread for each client
    thread1 = threading.Thread(target=handle_client, args=(clientsocket, addr))
    thread1.start()
