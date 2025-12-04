# discovery.py

import socket
import threading
import time
import json

BROADCAST_PORT = 5005
BROADCAST_INTERVAL = 3.0  # send every 3 seconds
PEER_TIMEOUT = 6.0        # offline if silent > 6 seconds

# email -> {name, ip, public_key, last_seen}
online_peers = {}


def _listener_thread(local_email: str):
    """Listen for UDP discovery packets and update online_peers."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", BROADCAST_PORT))

    while True:
        try:
            data, addr = s.recvfrom(4096)
            msg = data.decode("utf-8")

            info = json.loads(msg)

            email = info.get("email")
            name = info.get("name")
            public_key = info.get("public_key")

            # Ignore malformed packets
            if not email or not name or not public_key:
                continue

            # Ignore our own broadcasts
            if email == local_email:
                continue

            online_peers[email] = {
                "name": name,
                "ip": addr[0],
                "public_key": public_key,
                "last_seen": time.time(),
            }

        except Exception:
            # Ignore bad packets
            continue


def _broadcast_thread(session: dict):
    """Broadcast our identity (email, name, public_key) every few seconds."""
    email = session["email"]
    name = session["name"]
    public_key = session["public_key"]

    payload = json.dumps({
        "email": email,
        "name": name,
        "public_key": public_key,
    }).encode("utf-8")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while True:
        try:
            s.sendto(payload, ("<broadcast>", BROADCAST_PORT))
            time.sleep(BROADCAST_INTERVAL)
        except Exception:
            continue


def start_discovery(session: dict):
    """Start listener + broadcaster threads for this logged-in user."""
    t1 = threading.Thread(target=_listener_thread, args=(session["email"],), daemon=True)
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
