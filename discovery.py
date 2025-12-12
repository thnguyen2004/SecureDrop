# discovery.py

import socket
import threading
import time
from utils import rsa_encrypt_with_public_key, rsa_decrypt_with_private_key

BROADCAST_PORT = 5005
BROADCAST_INTERVAL = 3.0  # send every 3 seconds
PEER_TIMEOUT = 6.0        # offline if silent > 6 seconds

# email -> {name, ip, last_seen}
online_peers = {}


def _listener_thread(private_key_bytes):
    """Listen for UDP discovery packets."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", BROADCAST_PORT))

    while True:
        try:
            data, addr = s.recvfrom(4096)

            pk_len = int.from_bytes(data[:4], "big")
            public_key_bytes = data[4:4 + pk_len]
            identity_bytes = data[4 + pk_len:]

            identity = identity_bytes.decode("utf-8")

            if "|" not in identity:
                continue

            email, name = identity.split("|", 1)

            online_peers[email] = {
                "name": name,
                "ip": addr[0],
                "public_key": public_key_bytes.decode(),
                "last_seen": time.time()
            }

        except Exception:
            continue


def _broadcast_thread(session):
    email = session["email"]
    name = session["name"]

    identity = f"{email}|{name}".encode()
    public_key = session["public_key"].encode()
    pk_len = len(public_key).to_bytes(4, "big")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while True:
        try:
            packet = pk_len + public_key + identity
            s.sendto(packet, ("<broadcast>", BROADCAST_PORT))
            time.sleep(BROADCAST_INTERVAL)
        except Exception:
            continue


def start_discovery(session):
    """Start listener + broadcaster threads."""
    t1 = threading.Thread(target=_listener_thread, args=(session["private_key_bytes"],), daemon=True)
    t2 = threading.Thread(target=_broadcast_thread, args=(session,), daemon=True)
    t1.start()
    t2.start()


def get_online_peers():
    """Return peers seen recently."""
    now = time.time()
    return {
        email: info
        for email, info in online_peers.items()
        if now - info["last_seen"] <= PEER_TIMEOUT
    }