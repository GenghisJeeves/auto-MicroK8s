import base64
import ipaddress
import json
import logging
import os
import secrets
import socket
import sqlite3
import threading
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from typing import Any

# Cryptographic libraries
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_der_private_key,
    load_der_public_key,
)

# Configure logging
logger = logging.getLogger(__name__)

# Default database path
SNAP_COMMON = os.environ.get(
    "SNAP_COMMON",
    str(Path.home() / ".local" / "share" / "auto-microk8s"),
)
DATABASE_PATH = os.path.join(
    SNAP_COMMON,
    "neighbours.db",
)

# Path for storing our key pair
KEY_PATH = os.path.join(SNAP_COMMON, "keys")
PRIVATE_KEY_PATH = os.path.join(KEY_PATH, "private.key")
PUBLIC_KEY_PATH = os.path.join(KEY_PATH, "public.key")

# Ensure directories exist
os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
os.makedirs(KEY_PATH, exist_ok=True)

# Thread-local storage for database connections
_local = threading.local()


@dataclass
class Neighbour:
    """Data class for storing neighbor information"""

    name: str
    ip_address: ipaddress.IPv4Address | ipaddress.IPv6Address
    public_key: str  # Base64 encoded X25519 public key
    trusted: bool = False
    id: int | None = None

    def __post_init__(self):
        """Ensure ip_address is an IP address object"""
        if isinstance(self.ip_address, str):
            self.ip_address = ipaddress.ip_address(self.ip_address)


@contextmanager
def get_db_connection() -> Generator[sqlite3.Connection, None, None]:
    """
    Get a database connection from the pool or create a new one.
    Uses thread-local storage to avoid sharing connections between threads.
    """
    # Check if connection exists in thread-local storage
    if not hasattr(_local, "connection") or _local.connection is None:
        # Create a new connection
        _local.connection = sqlite3.connect(
            DATABASE_PATH,
            # Set timeout for busy waiting (in seconds)
            timeout=30.0,
        )
        # Enable foreign keys
        _local.connection.execute("PRAGMA foreign_keys = ON")
        # Row factory for easier access
        _local.connection.row_factory = sqlite3.Row

    try:
        # Yield the connection to the caller
        yield _local.connection
        # Commit any changes
        _local.connection.commit()
    except Exception as e:
        # Rollback on error
        _local.connection.rollback()
        logger.error(f"Database error: {str(e)}")
        raise


def init_database() -> None:
    """Initialize the database schema if it doesn't exist"""
    with get_db_connection() as conn:
        conn.execute(
            """
        CREATE TABLE IF NOT EXISTS neighbours (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            ip_version INTEGER NOT NULL,  -- 4 for IPv4, 6 for IPv6
            public_key TEXT NOT NULL,
            trusted BOOLEAN NOT NULL DEFAULT 0,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(ip_address)
        )
        """
        )

        # Add index on IP address for faster lookups
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ip_address ON neighbours (ip_address)"
        )

        # Check if the trusted column exists, add it if it doesn't
        try:
            conn.execute("SELECT trusted FROM neighbours LIMIT 1")
        except sqlite3.OperationalError:
            # Column doesn't exist, add it
            logger.info("Adding trusted column to neighbours table")
            conn.execute(
                "ALTER TABLE neighbours ADD COLUMN trusted BOOLEAN NOT NULL DEFAULT 0"
            )


def get_generate_key_pair() -> tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    """
    Generate a new X25519 key pair if it doesn't exist, or load existing one.

    Returns:
        Tuple of (private_key, public_key)
    """
    # Check if keys already exist
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        try:
            # Load existing keys
            with open(PRIVATE_KEY_PATH, "rb") as f:
                private_key_data = f.read()
                private_key = load_der_private_key(private_key_data, password=None)

            with open(PUBLIC_KEY_PATH, "rb") as f:
                public_key_data = f.read()
                public_key = load_der_public_key(public_key_data)

            if isinstance(private_key, x25519.X25519PrivateKey) and isinstance(
                public_key, x25519.X25519PublicKey
            ):
                logger.info("Loaded existing X25519 key pair")
                return private_key, public_key
            else:
                logger.warning("Stored keys are not X25519 keys, generating new ones")
        except Exception as e:
            logger.warning(f"Error loading keys, generating new ones: {e}")

    # Generate new key pair
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Save keys
    try:
        # Save private key in DER format
        private_key_data = private_key.private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_key_data)

        # Save public key in DER format
        public_key_data = public_key.public_bytes(
            encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
        )
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_key_data)

        # Set secure permissions for private key
        os.chmod(PRIVATE_KEY_PATH, 0o600)

        logger.info("Generated and saved new X25519 key pair")
    except Exception as e:
        logger.error(f"Error saving keys: {e}")
        raise

    return private_key, public_key


def get_public_key_base64() -> str:
    """
    Get the local public key as a base64 string.

    Returns:
        Base64 encoded public key string
    """
    _, public_key = get_generate_key_pair()
    public_key_der = public_key.public_bytes(
        encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(public_key_der).decode("ascii")


def send_secure_message(
    neighbour: Neighbour, message: dict[str, Any], bypass_trust_check: bool = False
) -> dict[str, Any] | None:
    """
    Securely send a message to a neighbor using X25519 for key exchange
    and ChaCha20-Poly1305 for authenticated encryption.
    """
    # Check if neighbor is trusted, unless bypassing for a trust request
    if (
        not bypass_trust_check
        and not neighbour.trusted
        and message.get("type") != "trust_request"
    ):
        logger.warning(f"Cannot send message to untrusted neighbor: {neighbour.name}")
        return None

    try:
        # Get local key pair
        private_key, _ = get_generate_key_pair()

        # Decode recipient's public key
        recipient_public_key_bytes = base64.b64decode(neighbour.public_key)
        recipient_public_key = load_der_public_key(recipient_public_key_bytes)

        if not isinstance(recipient_public_key, x25519.X25519PublicKey):
            logger.error(f"Invalid public key format for neighbor: {neighbour.name}")
            return None

        # Perform key exchange
        shared_key = private_key.exchange(recipient_public_key)

        # Use shared key to create a ChaCha20Poly1305 cipher
        cipher = ChaCha20Poly1305(shared_key[:32])  # Use first 32 bytes as key

        # Generate a nonce
        nonce = secrets.token_bytes(12)  # 12 bytes is the required nonce size

        # Serialize the message to JSON using double quotes (default for json.dumps)
        message_json = json.dumps(message).encode("utf-8")

        # Log the properly formatted JSON message for debugging
        logger.debug(f"Sending JSON message: {message_json.decode('utf-8')}")

        # Encrypt the message
        encrypted_message = cipher.encrypt(nonce, message_json, None)

        # Combine nonce and ciphertext for transmission
        payload = {
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(encrypted_message).decode("ascii"),
            "sender_key": get_public_key_base64(),
        }

        # Actually send the message to the neighbor's API endpoint
        import requests
        from requests.exceptions import RequestException

        try:
            # Construct the URL using the neighbor's IP address and assumed port
            url = f"http://{neighbour.ip_address}:8800/api/secure-message"

            # Send the POST request with the encrypted payload - requests.post handles JSON encoding properly
            response = requests.post(
                url,
                json=payload,  # This uses json.dumps internally with proper double quotes
                headers={"Content-Type": "application/json"},
                timeout=10,  # Set a reasonable timeout
            )

            # Check if the request was successful
            if response.status_code == 200:
                logger.info(
                    f"Message sent successfully to {neighbour.name} ({neighbour.ip_address})"
                )

                # If there's a response, try to parse it
                try:
                    return response.json()
                except ValueError:
                    logger.warning(f"Received non-JSON response from {neighbour.name}")
                    return None
            else:
                # Fix the error log to not print the raw payload which shows single quotes
                logger.error(
                    f"Failed to send message to {neighbour.name}: HTTP {response.status_code}"
                )
                return None

        except RequestException as e:
            logger.error(f"Network error sending message to {neighbour.name}: {e}")
            return None

    except Exception as e:
        logger.error(f"Error sending secure message: {e}")
        return None


def receive_secure_message(
    sender_key_base64: str,
    nonce_base64: str,
    ciphertext_base64: str,
    bypass_trust_check: bool = False,
) -> dict[str, Any] | None:
    """
    Receive and decrypt a secure message from a neighbor.

    Args:
        sender_key_base64: Base64-encoded public key of the sender
        nonce_base64: Base64-encoded nonce
        ciphertext_base64: Base64-encoded encrypted message
        bypass_trust_check: If True, accept messages from untrusted neighbors

    Returns:
        Decrypted message dictionary or None if failed
    """
    try:
        # Find the neighbor by public key
        sender = None
        all_neighbours = get_all_neighbours()
        for n in all_neighbours:
            if n.public_key == sender_key_base64:
                sender = n
                break

        if not sender:
            if bypass_trust_check:
                # We don't know the sender.
                # We're bypassing trust check so we can trust the embedded key
                logger.info(
                    f"Received message from unknown sender key: {sender_key_base64[:16]} - Continuing as bypass_trust_check in force."
                )

            else:
                # If we don't know the sender, log a warning and ignore the message
                logger.warning(
                    f"Received message from unknown sender key: {sender_key_base64[:16]}..."
                )
                return None
        # Check if neighbor is trusted
        elif not sender.trusted:
            # If bypass_trust_check
            if bypass_trust_check:
                logger.debug(
                    f"Processing message from untrusted neighbor: {sender.name} (bypass trust check)"
                )
            else:
                # If not bypassing trust check, ignore the message
                logger.warning(
                    f"Ignoring message from untrusted neighbor: {sender.name}"
                )
                return None

        # Get local private key
        private_key, _ = get_generate_key_pair()
        logger.debug(f"Got local private key {private_key}")

        # Decode sender's public key
        sender_public_key_bytes = base64.b64decode(sender_key_base64)
        sender_public_key = load_der_public_key(sender_public_key_bytes)

        if not isinstance(sender_public_key, x25519.X25519PublicKey):
            logger.error("Invalid sender public key format")
            return None
        else:
            logger.info("Successfully retrieved sender's public key")

        # Perform key exchange
        shared_key = private_key.exchange(sender_public_key)
        logger.debug("Performed key exchange")

        # Create cipher
        cipher = ChaCha20Poly1305(shared_key[:32])
        logger.debug("Created cipher")

        # Decode nonce and ciphertext
        nonce = base64.b64decode(nonce_base64)
        ciphertext = base64.b64decode(ciphertext_base64)

        # Decrypt the message
        decrypted_data = cipher.decrypt(nonce, ciphertext, None)
        logger.debug(f"Decrypted data is {decrypted_data}")

        # Parse JSON message
        message = json.loads(decrypted_data.decode("utf-8"))
        logger.debug(f"Parsed JSON is {message}")

        logger.info(
            f"Successfully decrypted message with public key {sender_key_base64}"
        )
        return message

    except Exception as e:
        logger.error(f"Error receiving secure message: {e}")
        return None


def add_neighbour(neighbour: Neighbour) -> int | None:
    """
    Add a new neighbor if a neighbor with the same IP address does not exist.
    If a neighbor with the same IP address exists, do not do anything.
    The old IP must fist be removed before adding a new one.

    Args:
        neighbour: The Neighbour object to add or update

    Returns:
        The ID of the added or updated neighbor
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Convert IP address to string for storage
        ip_str = str(neighbour.ip_address)
        ip_version = 4 if isinstance(neighbour.ip_address, ipaddress.IPv4Address) else 6

        # Check if neighbor with this IP already exists
        cursor.execute(
            "SELECT id, trusted FROM neighbours WHERE ip_address = ?", (ip_str,)
        )
        result = cursor.fetchone()

        neighbour_id: int | None = None

        if result:
            logger.warning(
                f"IP already exists please remove old entry if no longer in use {neighbour.name} at {ip_str}"
            )
        else:
            # Insert new neighbor
            cursor.execute(
                """
            INSERT INTO neighbours (name, ip_address, ip_version, public_key, trusted)
            VALUES (?, ?, ?, ?, ?)
            """,
                (
                    neighbour.name,
                    ip_str,
                    ip_version,
                    neighbour.public_key,
                    neighbour.trusted,
                ),
            )
            if type(cursor.lastrowid) is int:
                neighbour_id = cursor.lastrowid
                logger.debug(f"Added new neighbour {neighbour.name} at {ip_str}")
            else:
                logger.error("Failed to retrieve last inserted row ID")
                raise ValueError("Failed to add neighbour, no ID returned")

        return neighbour_id


def set_neighbour_trusted(
    ip_address: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
    trusted: bool = True,
) -> bool:
    """
    Set the trusted status for a neighbor

    Args:
        ip_address: The IP address of the neighbor
        trusted: Whether to mark as trusted (True) or untrusted (False)

    Returns:
        True if the neighbor was found and updated, False otherwise
    """
    # Ensure IP is in string format for query
    if not isinstance(ip_address, str):
        ip_address = str(ip_address)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE neighbours SET trusted = ? WHERE ip_address = ?",
            (trusted, ip_address),
        )
        return cursor.rowcount > 0


def get_neighbour_by_ip(
    ip_address: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> Neighbour | None:
    """
    Retrieve a neighbor by IP address

    Args:
        ip_address: The IP address to search for

    Returns:
        A Neighbour object if found, None otherwise
    """
    # Ensure IP is in string format for query
    if not isinstance(ip_address, str):
        ip_address = str(ip_address)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, name, ip_address, public_key, trusted FROM neighbours WHERE ip_address = ?",
            (ip_address,),
        )
        row = cursor.fetchone()

        if row:
            return Neighbour(
                id=row["id"],
                name=row["name"],
                ip_address=ipaddress.ip_address(row["ip_address"]),
                public_key=row["public_key"],
                trusted=bool(row["trusted"]),
            )
        return None


def get_all_neighbours() -> list[Neighbour]:
    """
    Retrieve all stored neighbors

    Returns:
        A list of Neighbour objects
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, name, ip_address, public_key, trusted FROM neighbours ORDER BY name"
        )
        rows = cursor.fetchall()

        return [
            Neighbour(
                id=row["id"],
                name=row["name"],
                ip_address=ipaddress.ip_address(row["ip_address"]),
                public_key=row["public_key"],
                trusted=bool(row["trusted"]),
            )
            for row in rows
        ]


def get_trusted_neighbours() -> list[Neighbour]:
    """
    Retrieve only trusted neighbors

    Returns:
        A list of trusted Neighbour objects
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, name, ip_address, public_key, trusted FROM neighbours WHERE trusted = 1 ORDER BY name"
        )
        rows = cursor.fetchall()

        return [
            Neighbour(
                id=row["id"],
                name=row["name"],
                ip_address=ipaddress.ip_address(row["ip_address"]),
                public_key=row["public_key"],
                trusted=True,
            )
            for row in rows
        ]


def remove_neighbour(
    ip_address: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """
    Remove a neighbor from storage

    Args:
        ip_address: The IP address of the neighbor to remove

    Returns:
        True if a neighbor was removed, False otherwise
    """
    # Ensure IP is in string format for query
    if not isinstance(ip_address, str):
        ip_address = str(ip_address)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM neighbours WHERE ip_address = ?", (ip_address,))

        return cursor.rowcount > 0


def cleanup_stale_neighbours(max_age_hours: int = 24) -> int:
    """
    Remove neighbors that haven't been seen for a specified time

    Args:
        max_age_hours: Maximum age in hours before a neighbor is considered stale

    Returns:
        Number of removed neighbors
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM neighbours WHERE last_seen < datetime('now', '-' || ? || ' hours')",
            (max_age_hours,),
        )
        return cursor.rowcount


def get_local_ip() -> IPv4Address | IPv6Address:
    try:
        # Create a temporary socket to determine our IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("aw6.uk", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip_address(ip)
    except Exception as e:
        logger.error(f"Error getting local IP: {e}")
        return ip_address("127.0.0.1")


def check_neighbor_trusts_us(neighbour: Neighbour) -> bool:
    """
    Check if a neighbor trusts us by sending a status request

    Args:
        neighbour: The neighbor to check

    Returns:
        True if the neighbor trusts us, False otherwise
    """
    if not neighbour.trusted:
        return False

    try:
        # Send a status request
        local_ip: IPv4Address | IPv6Address = get_local_ip()
        message = {
            "type": "trust_status_request",
            "sender_ip": str(local_ip),
            "timestamp": datetime.now().isoformat(),
        }

        response = send_secure_message(neighbour, message)
        if response:
            return bool(response.get("trusts_us", False))

        return False
    except Exception as e:
        logger.error(f"Error checking if neighbor trusts us: {e}")
        return False


# Initialize database and key pair when module is imported
init_database()
get_generate_key_pair()


if __name__ == "__main__":
    # Example usage when script is run directly
    logging.basicConfig(level=logging.INFO)

    # Get our public key
    my_public_key = get_public_key_base64()
    print(f"My public key: {my_public_key[:20]}...")

    # Add a test neighbour
    test_neighbour = Neighbour(
        name="test-node-1",
        ip_address=ipaddress.ip_address("192.168.1.100"),
        public_key=my_public_key,  # Use our key for testing
    )

    add_neighbour(test_neighbour)

    # Set the neighbor as trusted
    set_neighbour_trusted(test_neighbour.ip_address, True)

    # List all neighbours
    all_neighbours = get_all_neighbours()
    for n in all_neighbours:
        trust_status = "trusted" if n.trusted else "untrusted"
        print(
            f"Neighbour: {n.name}, IP: {n.ip_address}, Key: {n.public_key[:20]}..., Status: {trust_status}"
        )

    # Test sending a message to the trusted neighbor
    message = {"type": "hello", "content": "This is a test message"}
    response = send_secure_message(test_neighbour, message)

    if response:
        print(f"Message sent, response: {response}")
    else:
        print("Failed to send message")
