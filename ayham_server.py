# ayham_server.py
# Person 1: September 29 checkpoint
# Requires Person 3's packets.py module.

import socket
import threading
from pathlib import Path

from packets import ProtocolError, encode_field, receive_packet, send_packet


HOST = "127.0.0.1"
PORT = 5050

PROTOCOL_NAME = "RFMP"
PROTOCOL_VERSION = "v1.0"

SERVER_ROOT = Path(__file__).resolve().parent / "server_storage"


def send_error(connection, code, description):
    """Send an EE packet if the client is still connected."""
    try:
        send_packet(
            connection,
            "EE",
            [str(code), encode_field(description.encode("utf-8"))],
        )
    except OSError:
        pass


def perform_server_setup(connection, session):
    """Receive SS, validate it, and send CC."""
    packet_type, fields = receive_packet(connection)

    if packet_type != "SS" or len(fields) != 3:
        raise ProtocolError("Expected SS with three fields.")

    protocol_name, version, secure = fields

    if protocol_name != PROTOCOL_NAME:
        raise ProtocolError("Unsupported protocol name.")

    if version != PROTOCOL_VERSION:
        raise ProtocolError("Unsupported protocol version.")

    if secure not in ("0", "1"):
        raise ProtocolError("Security flag must be 0 or 1.")

    if secure == "1":
        send_error(connection, 4, "Encrypted setup is not implemented yet.")
        return False

    send_packet(connection, "CC", [])
    session["state"] = "READY"

    return True


def handle_client(connection, address):
    """Manage one client connection and its own session."""

    # Every call creates a separate dictionary for this client.
    session = {
        "state": "WAIT_START",
        "current_directory": SERVER_ROOT,
        "security_mode": "NONE",
        "session_key": b"",
        "username": None,
        "client_public_key": None,
        "pending_write_path": None,
    }

    print(f"Client connected: {address}")

    try:
        if not perform_server_setup(connection, session):
            return

        print(f"Handshake completed: {address}")

        while session["state"] == "READY":
            packet_type, fields = receive_packet(connection)

            if packet_type == "End":
                send_packet(connection, "SC", [encode_field(b"BYE")])
                break

            if packet_type == "CM":
                send_error(connection, 3, "Commands are not implemented yet.")
            else:
                send_error(connection, 1, "Expected CM or End after setup.")

    except ProtocolError as error:
        send_error(connection, 1, str(error))

    except EOFError:
        print(f"Client disconnected unexpectedly: {address}")

    except OSError as error:
        print(f"Connection error for {address}: {error}")

    finally:
        session["state"] = "CLOSED"
        session["pending_write_path"] = None
        connection.close()

        print(f"Connection closed: {address}")


def start_server():
    """Listen for connections and start one thread per client."""
    SERVER_ROOT.mkdir(parents=True, exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        server.bind((HOST, PORT))
        server.listen()

        print(f"RFMP server listening on {HOST}:{PORT}")
        print("Press Ctrl+C to stop.")

        while True:
            connection, address = server.accept()

            client_thread = threading.Thread(
                target=handle_client,
                args=(connection, address),
                daemon=True,
            )

            client_thread.start()


if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    except OSError as error:
        raise SystemExit(f"Could not run the server: {error}")
