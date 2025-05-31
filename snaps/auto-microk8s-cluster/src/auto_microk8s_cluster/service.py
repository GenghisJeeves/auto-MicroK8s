import argparse
import json
import logging
import os
import socket
import threading
import time
from collections.abc import Callable
from datetime import datetime, timedelta
from functools import wraps
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from typing import Any, NoReturn, TypeVar, cast

import bcrypt
from flask import (
    Flask,
    Response,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

# Import neighbor functions and classes
from .neighbours import (
    Neighbour,
    add_neighbour,
    get_neighbour_by_ip,
    get_public_key_base64,
    set_neighbour_trusted,
)
from .setup_system import setup_system

# ToDo: If no password is set, ask the user for a password or register with the cloud
# ToDo: Broadcast trusted keys in a message signed by this server's key
# ToDo: If a broadcast is recieved from a trusted nighbour trust the keys that it trusts


# Define argument defaults - will be used when imported
class Args:
    def __init__(self):
        self.loglevel = "info"
        self.port = 8800
        self.discovery_port = 8801


# Create default args object that will be used unless parse_args is called
args = Args()


def parse_arguments():
    """Parse command line arguments only when script is run directly"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-log",
        "--loglevel",
        default="info",
        help="Provide logging level. Example --loglevel debug, default=warning",
    )
    parser.add_argument(
        "--port",
        default=8800,
        type=int,
        help="Port to run the web service on, default=8800",
    )
    parser.add_argument(
        "--discovery-port",
        default=8801,
        type=int,
        help="Port for discovery broadcasts, default=8801",
    )

    global args
    args = parser.parse_args()


# Configure logging - use default args initially
logger = logging.getLogger(__name__)
logging.basicConfig(level="INFO")  # Default level until args are parsed

# Path for password storage
SNAP_COMMON = os.environ.get(
    "SNAP_COMMON",
    str(Path.home() / ".local" / "share" / "auto-microk8s"),
)
PASSWORD_FILE = os.path.join(SNAP_COMMON, "password.hash")
os.makedirs(SNAP_COMMON, exist_ok=True)

# Create Flask app with template folder
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))
app.config["SESSION_TYPE"] = "filesystem"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=24)


# Store discovered neighbors
neighbors: dict[IPv4Address | IPv6Address, dict[str, Any]] = {}
neighbors_lock = threading.Lock()


# Get local IP address
def get_local_ip() -> IPv4Address | IPv6Address:
    try:
        # Create a temporary socket to determine our IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("google.com", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip_address(ip)
    except Exception as e:
        logger.error(f"Error getting local IP: {e}")
        return ip_address("127.0.0.1")


# Get local hostname
def get_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception as e:
        logger.error(f"Error getting hostname: {e}")
        return "unknown-host"


LOCAL_IP = get_local_ip()
LOCAL_HOSTNAME = get_hostname()
BROADCAST_INTERVAL = 30  # seconds
NODE_TIMEOUT = 90  # seconds


# Password management functions
def is_password_set() -> bool:
    """Check if a password has been set"""
    return os.path.exists(PASSWORD_FILE) and os.path.getsize(PASSWORD_FILE) > 0


def verify_password(password: str) -> bool:
    """Verify a password against the stored hash"""
    if not is_password_set():
        return False

    try:
        with open(PASSWORD_FILE, "rb") as f:
            stored_hash = f.read()

        # Verify the password
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash)
    except Exception as e:
        logger.error(f"Error verifying password: {e}")
        return False


def set_password(password: str) -> bool:
    """Hash and store a new password"""
    try:
        # Generate a salt and hash the password
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        # Write the hash to the file
        with open(PASSWORD_FILE, "wb") as f:
            f.write(password_hash)

        os.chmod(PASSWORD_FILE, 0o600)  # Secure the password file
        return True
    except Exception as e:
        logger.error(f"Error setting password: {e}")
        return False


# Authentication decorator
F = TypeVar("F", bound=Callable[..., Any])


def login_required(f: F) -> F:
    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        if not is_password_set():
            return redirect(url_for("setup_password"))

        if not session.get("authenticated"):
            return redirect(url_for("login", next=request.url))

        return f(*args, **kwargs)

    return cast(F, decorated_function)


# Discovery service
def send_discovery_broadcast() -> NoReturn:
    """Send periodic UDP broadcasts to announce this service's presence"""
    # Get the public key once before entering the loop
    public_key = get_public_key_base64()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while True:
            try:
                message = json.dumps(
                    {
                        "ip": str(LOCAL_IP),  # Convert to string for JSON
                        "port": args.port,
                        "hostname": LOCAL_HOSTNAME,
                        "public_key": public_key,
                        "timestamp": datetime.now().isoformat(),
                    }
                )
                sock.sendto(message.encode(), ("<broadcast>", args.discovery_port))
                logger.debug(
                    f"Sent discovery broadcast from {LOCAL_HOSTNAME} ({LOCAL_IP}:{args.port})"
                )
            except Exception as e:
                logger.error(f"Error sending discovery broadcast: {e}")

            time.sleep(BROADCAST_INTERVAL)


def listen_for_broadcasts() -> NoReturn:
    """Listen for broadcasts from other services"""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", args.discovery_port))

        while True:
            try:
                data, addr = sock.recvfrom(1024)
                sender_ip = ip_address(addr[0])  # Convert to ip_address object

                # Skip our own broadcasts
                if sender_ip == LOCAL_IP:
                    continue

                info = json.loads(data.decode())

                # Extract information from broadcast
                hostname = info.get("hostname", f"unknown-{str(sender_ip)}")
                public_key = info.get("public_key", "")
                port = info.get("port", args.port)

                # Store in memory cache
                with neighbors_lock:
                    neighbors[sender_ip] = {
                        "ip": sender_ip,
                        "hostname": hostname,
                        "port": port,
                        "public_key": public_key,
                        "last_seen": datetime.now(),
                    }

                # Store in persistent database
                if public_key:  # Only store if public key is provided
                    # Create neighbor object
                    new_neighbor = Neighbour(
                        name=hostname,
                        ip_address=sender_ip,
                        public_key=public_key,
                        # Default to untrusted
                        trusted=False,
                    )

                    # Check if we already know this neighbor
                    existing = get_neighbour_by_ip(sender_ip)
                    if not existing:
                        # Add to database if new
                        add_neighbour(new_neighbor)
                        logger.info(
                            f"Discovered new neighbor: {hostname} at {sender_ip}"
                        )
                    else:
                        # Just log that we saw them again
                        logger.debug(
                            f"Received heartbeat from known neighbor: {hostname} at {sender_ip}"
                        )
                else:
                    logger.warning(
                        f"Received broadcast without public key from {sender_ip}, ignoring for security"
                    )

            except Exception as e:
                logger.error(f"Error receiving discovery broadcast: {e}")


def cleanup_neighbors() -> NoReturn:
    """Remove stale neighbors"""
    while True:
        time.sleep(10)
        # Clean up in-memory cache
        stale = [
            ip
            for ip, data in neighbors.items()
            if datetime.now() - data["last_seen"] > timedelta(seconds=NODE_TIMEOUT)
        ]
        for ip in stale:
            logger.info(f"Removing stale neighbor from cache: {ip}")
            with neighbors_lock:
                if ip in neighbors:
                    del neighbors[ip]


# Web Service Routes
@app.route("/")
def home() -> Response:
    if not is_password_set():
        return redirect(url_for("setup_password"))

    if not session.get("authenticated"):
        return redirect(url_for("login"))

    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if not is_password_set():
        return redirect(url_for("setup_password"))

    error = None
    if request.method == "POST":
        password = request.form.get("password", "")

        if verify_password(password):
            session["authenticated"] = True
            flash("Login successful!", "success")
            next_page = request.args.get("next")
            if next_page:
                return redirect(next_page)
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid password"

    return render_template("login.html", error=error)


@app.route("/setup-password", methods=["GET", "POST"])
def setup_password():
    if is_password_set():
        flash("Password is already set.", "info")
        return redirect(url_for("login"))

    error = None
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not password:
            error = "Password cannot be empty"
        elif password != confirm:
            error = "Passwords do not match"
        else:
            if set_password(password):
                session["authenticated"] = True
                flash("Password set successfully!", "success")
                return redirect(url_for("dashboard"))
            else:
                error = "Error setting password"

    return render_template("setup_password.html", error=error)


@app.route("/logout")
def logout():
    session.pop("authenticated", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/neighbors")
def list_neighbors() -> Response:
    with neighbors_lock:
        active_neighbors: dict[str, dict[str, Any]] = {
            str(ip): {  # Convert ip_address key to string for JSON
                "ip": str(data["ip"]),
                "hostname": data.get("hostname", "unknown"),
                "port": data["port"],
                "last_seen": data["last_seen"].isoformat(),
                "has_public_key": bool(data.get("public_key", "")),
            }
            for ip, data in neighbors.items()
        }

    return jsonify(
        {
            "this_node": {
                "hostname": LOCAL_HOSTNAME,
                "ip": str(LOCAL_IP),
                "port": args.port,
            },
            "neighbors": active_neighbors,
            "count": len(active_neighbors),
        }
    )


# Add a new API endpoint to trust a neighbor
@app.route("/neighbors/<ip>/trust", methods=["POST"])
@login_required
def trust_neighbor(ip: str) -> Response | tuple[Response, int]:
    try:
        # Convert string to IP address
        neighbor_ip = ip_address(ip)

        # Trust the neighbor
        if set_neighbour_trusted(neighbor_ip, True):
            flash(f"Neighbor {ip} is now trusted!", "success")
        else:
            flash(f"Neighbor {ip} not found.", "error")

    except ValueError:
        flash("Invalid IP address", "error")
    except Exception as e:
        logger.error(f"Error trusting neighbor: {e}")
        flash(f"Error: {str(e)}", "error")

    return redirect(url_for("dashboard"))


@app.route("/neighbors/<ip>/untrust", methods=["POST"])
@login_required
def untrust_neighbor(ip: str) -> Response | tuple[Response, int]:
    try:
        # Convert string to IP address
        neighbor_ip = ip_address(ip)

        # Untrust the neighbor
        if set_neighbour_trusted(neighbor_ip, False):
            flash(f"Neighbor {ip} is now untrusted.", "success")
        else:
            flash(f"Neighbor {ip} not found.", "error")

    except ValueError:
        flash("Invalid IP address", "error")
    except Exception as e:
        logger.error(f"Error untrusting neighbor: {e}")
        flash(f"Error: {str(e)}", "error")

    return redirect(url_for("dashboard"))


# API routes (for compatibility with existing clients)
@app.route("/api")
def api_info():
    if not session.get("authenticated"):
        return jsonify({"error": "Not authenticated"}), 401

    return jsonify(
        {
            "service": "Auto MicroK8s Cluster",
            "status": "running",
            "hostname": LOCAL_HOSTNAME,
            "ip": str(LOCAL_IP),
            "port": args.port,
        }
    )


@app.route("/api/neighbors")
def api_list_neighbors():
    if not session.get("authenticated"):
        return jsonify({"error": "Not authenticated"}), 401

    with neighbors_lock:
        active_neighbors: dict[str, dict[str, Any]] = {
            str(ip): {
                "ip": str(data["ip"]),
                "hostname": data.get("hostname", "unknown"),
                "port": data["port"],
                "last_seen": data["last_seen"].isoformat(),
                "has_public_key": bool(data.get("public_key", "")),
            }
            for ip, data in neighbors.items()
        }

    return jsonify(
        {
            "this_node": {
                "hostname": LOCAL_HOSTNAME,
                "ip": str(LOCAL_IP),
                "port": args.port,
            },
            "neighbors": active_neighbors,
            "count": len(active_neighbors),
        }
    )


def main() -> None:
    """Main function for the service."""
    # Update logging with the parsed arguments
    logging.basicConfig(level=args.loglevel.upper())
    logger.info("Logging now setup.")

    logger.info(
        f"Auto MicroK8s Cluster service started on {LOCAL_HOSTNAME} ({LOCAL_IP}:{args.port})"
    )

    try:
        # Set up MicroK8s using the imported function
        setup_result = setup_system()
        if not setup_result:
            logger.warning("MicroK8s setup may not be complete, continuing anyway")

        # Start the discovery broadcast thread
        broadcast_thread = threading.Thread(
            target=send_discovery_broadcast, daemon=True
        )
        broadcast_thread.start()

        # Start the thread to listen for broadcasts
        listen_thread = threading.Thread(target=listen_for_broadcasts, daemon=True)
        listen_thread.start()

        # Start the cleanup thread
        cleanup_thread = threading.Thread(target=cleanup_neighbors, daemon=True)
        cleanup_thread.start()

        # Start the web server
        app.run(host="0.0.0.0", port=args.port, debug=False)

    except KeyboardInterrupt:
        logger.info("Auto MicroK8s Cluster service stopped.")
    except Exception as e:
        logger.error(f"Service encountered an error: {e}")


if __name__ == "__main__":
    # Only parse arguments when running directly
    parse_arguments()
    main()
