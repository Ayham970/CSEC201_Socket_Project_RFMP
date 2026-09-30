# ayham_server.py
# RFMP Server - Person 1
# Day 1 (Sep 29): listening server, one thread per client,
# separate session record, unencrypted SS -> CC, and End.
# Uses Person 3's packets.py for framing and Base64.

import socket
import threading
import os

from packets import send_packet, receive_packet, encode_field, ProtocolError

HOST = "127.0.0.1"
PORT = 5050

PROTOCOL_NAME = "RFMP"
PROTOCOL_VERSION = "v1.0"

# server_storage/ is next to this script (protocol.md section 1)
SERVER_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server_storage")

# Error codes (protocol.md section 8.2)
# 1 = protocol error
# 2 = file or path error
# 3 = command error
# 4 = encryption error


def send_error(clientsocket, code, description):
    # EE packet: (EE,code,B64(description))
    send_packet(clientsocket, "EE", [str(code), encode_field(description.encode("utf-8"))])


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
        while session["state"] == "READY":
            packet_type, fields = receive_packet(clientsocket)

            # ---------- CLOSING PHASE ----------
            if packet_type == "End":
                # (SC,B64("BYE")) = (SC,QllF)
                send_packet(clientsocket, "SC", [encode_field(b"BYE")])
                break

            elif packet_type == "CM":
                # Commands are added on Day 2
                send_error(clientsocket, 3, "Commands not implemented yet")

            else:
                send_error(clientsocket, 1, "Expected CM or End")

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
