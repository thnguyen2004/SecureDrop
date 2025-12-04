"""
Milestone 5: Secure File Transfer

Implements secure, chunked file transfer with:
- Confidentiality (AES-256-GCM encryption per chunk)
- Integrity (HMAC per packet + SHA-256 hash of entire file)
- Replay attack prevention (sequence numbers with random seed)
- Large file support (64KB chunks)
"""

import os
import json
import socket
import hashlib
import base64
import threading
from pathlib import Path
from Crypto.Cipher import AES

# Configuration
CHUNK_SIZE = 64 * 1024  # 64KB chunks
FILE_TRANSFER_PORT = 5007
TIMEOUT = 30  # 30 second timeout for transfers


class FileTransferProtocol:
    """Handles secure file transfer between authenticated peers."""
    
    def __init__(self, session: dict):
        """
        Initialize file transfer with user session.
        Args:
            session: User session dict containing private key, email, etc.
        """
        self.session = session
        self.active_transfers = {}  # Track ongoing transfers
        self.transfer_lock = threading.Lock()
        
    def _derive_session_key(self, peer_email: str) -> bytes:
        """
        Derive a unique session key for this peer.
        """
        # Combine our identity with peer's email
        key_material = (
            self.session["email"] + 
            peer_email + 
            str(self.session["private_key_bytes"][:32])
        ).encode()
        
        # Generate 32-byte key using SHA-256
        return hashlib.sha256(key_material).digest()
    
    def _compute_file_hash(self, filepath: Path) -> str:
        """
        Compute SHA-256 hash of entire file for integrity verification.
        """
        sha256 = hashlib.sha256()
        
        with open(filepath, 'rb') as f:
            while chunk := f.read(CHUNK_SIZE):
                sha256.update(chunk)
        
        return sha256.hexdigest()
    
    def _generate_hmac(self, key: bytes, data: bytes) -> str:
        """
        Generate HMAC-SHA256 for data integrity.
        """
        import hmac as hmac_module
        h = hmac_module.new(key, data, hashlib.sha256)
        return h.hexdigest()
    
    def _verify_hmac(self, key: bytes, data: bytes, expected_hmac: str) -> bool:
        """
        Verify HMAC-SHA256.
        """
        import hmac as hmac_module
        computed = self._generate_hmac(key, data)
        return hmac_module.compare_digest(computed, expected_hmac)
    
    def _create_packet(self, packet_type: str, sequence: int, data: dict, 
                      session_key: bytes) -> bytes:
        """
        Create an encrypted, authenticated packet.
        """
        # Create packet
        packet = {
            "type": packet_type,
            "sequence": sequence,
            "sender": self.session["email"]
        }
        packet.update(data)
        
        # Serialize
        packet_json = json.dumps(packet).encode('utf-8')
        
        # Encrypt with AES-GCM
        cipher = AES.new(session_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(packet_json)
        
        encrypted = {
            "iv": base64.b64encode(cipher.nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "tag": base64.b64encode(tag).decode()
        }
        
        # Add HMAC for additional integrity
        encrypted_bytes = json.dumps(encrypted).encode('utf-8')
        hmac_value = self._generate_hmac(session_key, encrypted_bytes)
        
        final_packet = {
            "encrypted": encrypted,
            "hmac": hmac_value
        }
        
        return json.dumps(final_packet).encode('utf-8')
    
    def _verify_and_decrypt_packet(self, packet_bytes: bytes, session_key: bytes, expected_sequence: int) -> dict:

        """
        Verify and decrypt a packet, checking sequence number.
        """

        # Parse packet
        packet_data = json.loads(packet_bytes.decode('utf-8'))
        
        # Verify HMAC
        encrypted_bytes = json.dumps(packet_data["encrypted"]).encode('utf-8')
        if not self._verify_hmac(session_key, encrypted_bytes, packet_data["hmac"]):
            raise ValueError("HMAC verification failed - possible tampering!")
        
        # Decrypt
        encrypted = packet_data["encrypted"]
        ciphertext = base64.b64decode(encrypted["ciphertext"])
        nonce = base64.b64decode(encrypted["iv"])
        tag = base64.b64decode(encrypted["tag"])
        
        cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        packet_json = cipher.decrypt_and_verify(ciphertext, tag)
        
        packet = json.loads(packet_json.decode('utf-8'))
        
        # Verify sequence number (replay attack prevention)
        if expected_sequence is not None and packet["sequence"] != expected_sequence:
            raise ValueError(
                f"Sequence mismatch! Expected {expected_sequence}, "
                f"got {packet['sequence']}. Possible replay attack!"
            )
        
        return packet
    
    def send_file(self, filepath: Path, peer_email: str, peer_ip: str) -> bool:
        """
        Send a file securely to a peer.
        
        Protocol:
        1. Compute file hash
        2. Send METADATA packet (filename, size, hash, chunk count)
        3. Wait for READY confirmation
        4. Send encrypted CHUNK packets with sequence numbers
        5. Send COMPLETE packet
        6. Wait for VERIFIED confirmation

        """
        if not filepath.exists():
            print(f" Error: File '{filepath}' does not exist")
            return False
        
        try:
            # Derive session key for this peer
            session_key = self._derive_session_key(peer_email)
            
            # Compute file hash
            print(f"\n Preparing to send: {filepath.name}")
            print(f"   Computing file hash...")
            file_hash = self._compute_file_hash(filepath)
            file_size = filepath.stat().st_size
            total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
            
            print(f"   Size: {file_size:,} bytes ({file_size / (1024*1024):.2f} MB)")
            print(f"   Hash: {file_hash[:16]}...")
            print(f"   Chunks: {total_chunks}")
            
            # Connect to peer
            print(f"\n Connecting to {peer_email} at {peer_ip}:{FILE_TRANSFER_PORT}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((peer_ip, FILE_TRANSFER_PORT))
            print(f"   Connected!")
            
            # Random sequence seed for replay protection
            sequence = int.from_bytes(os.urandom(4), 'big')
            print(f"   Sequence seed: {sequence}")
            
            # Send metadata
            print(f"\n Sending metadata...")
            metadata = {
                "filename": filepath.name,
                "size": file_size,
                "hash": file_hash,
                "chunks": total_chunks
            }
            
            metadata_packet = self._create_packet("METADATA", sequence, metadata, session_key)
            sock.send(metadata_packet)
            sequence += 1
            
            # Wait for READY
            response = sock.recv(4096)
            response_packet = self._verify_and_decrypt_packet(response, session_key, sequence)
            sequence += 1
            
            if response_packet["type"] != "READY":
                print(f" Receiver not ready: {response_packet.get('message', 'Unknown error')}")
                sock.close()
                return False
            
            print(f"   Receiver ready!")
            
            # Send file chunks
            print(f"\n Transferring {total_chunks} chunks...")
            chunks_sent = 0
            
            with open(filepath, 'rb') as f:
                while chunk := f.read(CHUNK_SIZE):
                    # Encrypt chunk
                    cipher = AES.new(session_key, AES.MODE_GCM)
                    encrypted_chunk, tag = cipher.encrypt_and_digest(chunk)
                    
                    chunk_data = {
                        "chunk_index": chunks_sent,
                        "iv": base64.b64encode(cipher.nonce).decode(),
                        "ciphertext": base64.b64encode(encrypted_chunk).decode(),
                        "tag": base64.b64encode(tag).decode()
                    }
                    
                    chunk_packet = self._create_packet("CHUNK", sequence, chunk_data, session_key)
                    sock.send(chunk_packet)
                    sequence += 1
                    
                    chunks_sent += 1
                    
                    # Progress indicator
                    progress = (chunks_sent / total_chunks) * 100
                    bar_length = 40
                    filled = int(bar_length * chunks_sent / total_chunks)
                    bar = ' ' * filled + ' ' * (bar_length - filled)
                    print(f'\r   [{bar}] {progress:.1f}% ({chunks_sent}/{total_chunks})', end='')
            
            print()  # New line after progress bar
            print(f" Sent {chunks_sent} chunks")
            
            # Send completion
            print(f"\n Sending completion signal...")
            completion_packet = self._create_packet(
                "COMPLETE", 
                sequence, 
                {"total_chunks": chunks_sent}, 
                session_key
            )
            sock.send(completion_packet)
            sequence += 1
            
            # Wait for verification
            print(f"   Waiting for receiver verification...")
            response = sock.recv(4096)
            verify_packet = self._verify_and_decrypt_packet(response, session_key, sequence)
            
            if verify_packet["type"] == "VERIFIED":
                received_hash = verify_packet["hash"]
                
                if received_hash == file_hash:
                    print(f"\n SUCCESS! File transfer complete and verified!")
                    print(f"   Hash match: {file_hash[:16]}...")
                    sock.close()
                    return True
                else:
                    print(f"\n FAILURE! Hash mismatch!")
                    print(f"   Expected: {file_hash}")
                    print(f"   Received: {received_hash}")
                    sock.close()
                    return False
            else:
                print(f"\n Verification failed: {verify_packet.get('message', 'Unknown')}")
                sock.close()
                return False
        
        except Exception as e:
            print(f"\n Error during file transfer: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def receive_file(self, save_dir: Path):
        """
        Start file transfer server to receive files.
        Runs in background thread.
        
        Args:
            save_dir: Directory to save received files
        """
        save_dir.mkdir(exist_ok=True)
        
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", FILE_TRANSFER_PORT))
        server.listen(5)
        
        print(f"✓ File transfer server listening on port {FILE_TRANSFER_PORT}")
        
        while True:
            try:
                client, addr = server.accept()
                
                # Handle transfer in new thread
                transfer_thread = threading.Thread(
                    target=self._handle_file_receive,
                    args=(client, addr, save_dir),
                    daemon=True
                )
                transfer_thread.start()
                
            except Exception as e:
                print(f"File transfer server error: {e}")
    
    def _handle_file_receive(self, client: socket.socket, addr: tuple, save_dir: Path):
        """
        Handle incoming file transfer.
        
        Args:
            client: Client socket
            addr: Client address
            save_dir: Directory to save file
        """
        filepath = None
        
        try:
            print(f"\n Incoming file transfer from {addr[0]}")
            
            # Receive metadata
            data = client.recv(4096)
            
            # Try with first packet structure
            first_packet = json.loads(data.decode('utf-8'))
            
            # Decrypt first packet to get sender
            # Simplified approach: try to decrypt and extract sender
            sender_email = None
            session_key = None
            metadata_packet = None
            
            # Try to decrypt with potential peer keys
            from contacts import load_contacts_for_user
            contacts = load_contacts_for_user(self.session["email"])
            
            for contact_email in contacts:
                try:
                    test_key = self._derive_session_key(contact_email)
                    metadata_packet = self._verify_and_decrypt_packet(data, test_key, None)
                    sender_email = metadata_packet["sender"]
                    session_key = test_key
                    print(f"   Identified sender: {sender_email}")
                    break
                except:
                    continue
            
            if not session_key:
                print(f"✗ Could not establish secure session with sender")
                print(f"   Make sure sender is in your contacts!")
                client.close()
                return
            
            # Extract metadata
            filename = metadata_packet["filename"]
            file_size = metadata_packet["size"]
            expected_hash = metadata_packet["hash"]
            total_chunks = metadata_packet["chunks"]
            sequence = metadata_packet["sequence"] + 1
            
            print(f"   Filename: {filename}")
            print(f"   Size: {file_size:,} bytes ({file_size / (1024*1024):.2f} MB)")
            print(f"   Expected hash: {expected_hash[:16]}...")
            print(f"   Chunks: {total_chunks}")
            
            # Prepare to receive
            filepath = save_dir / filename
            
            # Check if file exists
            if filepath.exists():
                print(f" File already exists, will overwrite")
            
            # Send READY
            print(f"\n Ready to receive...")
            ready_packet = self._create_packet("READY", sequence, {}, session_key)
            client.send(ready_packet)
            sequence += 1
            
            # Receive chunks
            chunks_received = 0
            
            with open(filepath, 'wb') as f:
                while chunks_received < total_chunks:
                    # Receive chunk packet
                    data = client.recv(CHUNK_SIZE + 4096)  # Extra space for packet overhead
                    
                    if not data:
                        break
                    
                    chunk_packet = self._verify_and_decrypt_packet(data, session_key, sequence)
                    sequence += 1
                    
                    if chunk_packet["type"] == "CHUNK":
                        # Decrypt chunk data
                        chunk_data = chunk_packet
                        ciphertext = base64.b64decode(chunk_data["ciphertext"])
                        nonce = base64.b64decode(chunk_data["iv"])
                        tag = base64.b64decode(chunk_data["tag"])
                        
                        cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
                        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                        
                        # Write to file
                        f.write(plaintext)
                        chunks_received += 1
                        
                        # Progress indicator
                        progress = (chunks_received / total_chunks) * 100
                        bar_length = 40
                        filled = int(bar_length * chunks_received / total_chunks)
                        bar = ' ' * filled + ' ' * (bar_length - filled)
                        print(f'\r   [{bar}] {progress:.1f}% ({chunks_received}/{total_chunks})', end='')
                    
                    elif chunk_packet["type"] == "COMPLETE":
                        print()  # New line
                        print(f"  Received {chunks_received} chunks")
                        break
            
            # Verify file integrity
            print(f"\n Verifying file integrity...")
            received_hash = self._compute_file_hash(filepath)
            
            if received_hash == expected_hash:
                print(f"   ✓ Hash verification PASSED!")
                print(f"   Hash: {received_hash[:16]}...")
                
                # Send verification success
                verify_packet = self._create_packet(
                    "VERIFIED",
                    sequence,
                    {"hash": received_hash},
                    session_key
                )
                client.send(verify_packet)
                
                print(f"\n SUCCESS! File received and verified!")
                print(f"   Saved to: {filepath}")
                
            else:
                print(f"   Hash verification FAILED!")
                print(f"   Expected: {expected_hash}")
                print(f"   Received: {received_hash}")
                
                # Delete corrupted file
                filepath.unlink()
                print(f"   Deleted corrupted file")
                
                # Send verification failure
                verify_packet = self._create_packet(
                    "VERIFICATION_FAILED",
                    sequence,
                    {"hash": received_hash},
                    session_key
                )
                client.send(verify_packet)
            
            client.close()
            
        except Exception as e:
            print(f"\n✗ Error receiving file: {e}")
            import traceback
            traceback.print_exc()
            
            # Clean up partial file
            if filepath and filepath.exists():
                filepath.unlink()
                print(f"   Cleaned up partial file")
            
            client.close()


def start_file_transfer_server(session: dict):
    """
    Start file transfer server in background thread.
    """
    protocol = FileTransferProtocol(session)
    save_dir = Path("received_files")
    
    server_thread = threading.Thread(
        target=protocol.receive_file,
        args=(save_dir,),
        daemon=True
    )
    server_thread.start()
    
    return protocol