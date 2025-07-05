import argparse
import base64
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
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug import Response

from .build_cluster import build_microk8s_cluster, join_microk8s_cluster

# Import neighbor functions and classes
from .neighbours import (
    Neighbour,
    add_neighbour,
    get_all_neighbours,
    get_neighbour_by_ip,
    get_public_key_base64,
    get_trusted_neighbours,
    receive_secure_message,
    send_secure_message,
    set_neighbour_trusted,
)
from .setup_system import setup_system

# ToDo: Broadcast trusted keys in a message signed by this server's key
# ToDo: If a broadcast is received from a trusted neighbour trust the keys that it trusts


# Define argument defaults - will be used when imported
class Args:
    def __init__(self):
        self.loglevel = "info"
        self.port = 8800
        self.discovery_port = 8801


# Create default args object that will be used unless parse_args is called
args = Args()


def parse_arguments():
    """Parse command line arguments"""
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

    # Parse sys.argv directly to ensure arguments are always processed
    import sys

    parsed_args = parser.parse_args(sys.argv[1:])

    # Update global args
    global args
    args.loglevel = parsed_args.loglevel
    args.port = parsed_args.port
    args.discovery_port = parsed_args.discovery_port

    return args


# Configure logging - use default args initially
logger = logging.getLogger(__name__)
# Don't call basicConfig yet - we'll do it after parsing args

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


# Add this decorator to set the XHTML content type
@app.after_request
def set_xhtml_content_type(response: Response) -> Response:
    """Set the correct Content-Type header for XHTML responses."""
    if response.mimetype == "text/html":
        response.headers["Content-Type"] = "application/xhtml+xml; charset=utf-8"
    return response


# Store discovered neighbors
neighbors: dict[IPv4Address | IPv6Address, dict[str, Any]] = {}
neighbors_lock = threading.Lock()


# Get local IP address
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
    is_set = os.path.exists(PASSWORD_FILE) and os.path.getsize(PASSWORD_FILE) > 0
    logger.debug(f"Password set check: {is_set}")
    return is_set


def verify_password(password: str) -> bool:
    """Verify a password against the stored hash"""
    if not is_password_set():
        logger.debug("Password verification failed: No password is set")
        return False

    try:
        with open(PASSWORD_FILE, "rb") as f:
            stored_hash = f.read()

        # Verify the password
        result = bcrypt.checkpw(password.encode("utf-8"), stored_hash)
        logger.debug(
            f"Password verification result: {'success' if result else 'failed'}"
        )
        return result
    except Exception as e:
        logger.error(f"Error verifying password: {e}")
        return False


def set_password(password: str) -> bool:
    """Hash and store a new password"""
    try:
        logger.info("Setting new management password")
        # Generate a salt and hash the password
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        # Write the hash to the file
        with open(PASSWORD_FILE, "wb") as f:
            f.write(password_hash)

        os.chmod(PASSWORD_FILE, 0o600)  # Secure the password file
        logger.info("Password set successfully")
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
    logger.info(f"Starting discovery broadcast service on port {args.discovery_port}")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        logger.debug("Discovery broadcast socket configured with SO_BROADCAST enabled")

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

            logger.debug(
                f"Sleeping for {BROADCAST_INTERVAL} seconds before next broadcast"
            )
            time.sleep(BROADCAST_INTERVAL)


def listen_for_broadcasts() -> NoReturn:
    """Listen for broadcasts from other services"""
    logger.info(f"Starting broadcast listener on port {args.discovery_port}")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", args.discovery_port))
        logger.debug(f"Broadcast listener socket bound to port {args.discovery_port}")

        while True:
            # 1. Receive data from socket
            try:
                logger.debug("Waiting for broadcast messages...")
                data, addr = sock.recvfrom(1024)
                logger.debug(f"Received {len(data)} bytes from {addr}")
            except (socket.error, OSError) as e:
                logger.error(f"Network error receiving broadcast: {e}")
                continue

            # 2. Process sender IP
            try:
                sender_ip = ip_address(addr[0])
                logger.debug(f"Processing broadcast from {sender_ip}")

                # Skip our own broadcasts
                if sender_ip == LOCAL_IP:
                    logger.debug("Ignoring our own broadcast")
                    continue

            except ValueError as e:
                logger.error(f"Invalid IP address received: {addr[0]} - {e}")
                continue

            # 3. Parse the message
            try:
                info = json.loads(data.decode())
                logger.debug(f"Parsed broadcast data: {info}")
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                logger.error(f"Failed to parse broadcast message: {e}")
                continue

            # 4. Extract information from broadcast
            hostname = info.get("hostname", f"unknown-{str(sender_ip)}")
            public_key = info.get("public_key", "")
            port = info.get("port", args.port)
            logger.debug(
                f"Extracted details - hostname: {hostname}, port: {port}, has_key: {bool(public_key)}"
            )

            # 5. Update in-memory neighbors cache
            with neighbors_lock:
                neighbors[sender_ip] = {
                    "ip": sender_ip,
                    "hostname": hostname,
                    "port": port,
                    "public_key": public_key,
                    "last_seen": datetime.now(),
                }
                logger.debug(
                    f"Updated in-memory cache for neighbor {hostname} ({sender_ip})"
                )

            # 6. Update persistent database if we have a public key
            if public_key:
                try:
                    # Create neighbor object
                    logger.debug(
                        f"Creating Neighbour object for {hostname} ({sender_ip})"
                    )
                    new_neighbor = Neighbour(
                        name=hostname,
                        ip_address=sender_ip,
                        public_key=public_key,
                        trusted=False,  # Default to untrusted
                    )

                    # Check if we already know this neighbor
                    existing = get_neighbour_by_ip(sender_ip)
                    if not existing:
                        # Add to database if new
                        logger.info(
                            f"Adding new neighbor to database: {hostname} ({sender_ip})"
                        )
                        add_neighbour(new_neighbor)
                        logger.info(
                            f"Discovered new neighbor: {hostname} at {sender_ip}"
                        )
                    else:
                        # Just log that we saw them again
                        logger.debug(
                            f"Received heartbeat from known neighbor: {hostname} at {sender_ip}"
                        )
                except ValueError as e:
                    logger.error(f"Error with neighbor data values: {e}")
            else:
                logger.warning(
                    f"Received broadcast without public key from {sender_ip}, ignoring for security"
                )


def cleanup_neighbors() -> NoReturn:
    """Remove stale neighbors"""
    logger.info("Starting neighbor cleanup service")
    while True:
        logger.debug("Checking for stale neighbors")
        time.sleep(10)
        # Clean up in-memory cache
        stale = [
            ip
            for ip, data in neighbors.items()
            if datetime.now() - data["last_seen"] > timedelta(seconds=NODE_TIMEOUT)
        ]

        if stale:
            logger.debug(f"Found {len(stale)} stale neighbors to remove")
            for ip in stale:
                logger.info(f"Removing stale neighbor from cache: {ip}")
                with neighbors_lock:
                    if ip in neighbors:
                        hostname = neighbors[ip].get("hostname", "unknown")
                        logger.info(f"Removing stale neighbor: {hostname} ({ip})")
                        del neighbors[ip]
        else:
            logger.debug("No stale neighbors found")


# Message handling for cluster commands
# Add a global variable to track cluster status
cluster_status = ""
cluster_status_lock = threading.Lock()


def handle_secure_message(message: dict[str, Any]) -> bool:
    """Handle secure messages from other nodes"""
    global cluster_status

    try:
        message_type = message.get("type", "")
        logger.debug(f"Processing secure message of type: {message_type}")

        if message_type == "cluster_join":
            join_command = message.get("command")
            if join_command:
                logger.info(f"Received cluster join command: {join_command}")

                # Update status
                with cluster_status_lock:
                    cluster_status = "Joining cluster..."
                    logger.debug(f"Updated cluster status: {cluster_status}")

                # Start a background thread to join the cluster
                logger.debug("Starting background thread to join cluster")
                join_thread = threading.Thread(
                    target=join_cluster_thread,
                    args=(join_command,),
                    daemon=True,
                )
                join_thread.start()
                return True

        elif message_type == "trust_request":
            # Handle trust request
            sender_ip = message.get("sender_ip")
            sender_hostname = message.get("sender_hostname")
            sender_public_key = message.get("sender_public_key")

            logger.debug(
                f"Processing trust request from {sender_hostname} ({sender_ip})"
            )

            if sender_ip and sender_hostname and sender_public_key:
                # Convert IP string to IP address object
                try:
                    ip_obj = ip_address(sender_ip)

                    # Check if we have a password set - determines trust behavior
                    password_set = is_password_set()
                    logger.debug(
                        f"Password set check for trust decision: {password_set}"
                    )

                    if password_set:
                        # If password is set, we require manual trust approval
                        logger.info(
                            f"Received trust request from {sender_hostname} ({sender_ip}). "
                            f"Manual approval required as management password is set."
                        )
                        flash(
                            f"Received trust request from {sender_hostname} ({sender_ip})",
                            "info",
                        )
                        return True  # Acknowledge receipt
                    else:
                        # No password - automatically trust and request password from sender
                        logger.info(
                            f"Auto-trusting {sender_hostname} ({sender_ip}) as we have no password set"
                        )

                        # Create neighbor object
                        new_neighbor = Neighbour(
                            name=sender_hostname,
                            ip_address=ip_obj,
                            public_key=sender_public_key,
                            trusted=True,  # Auto-trust
                        )

                        # Check if we already know this neighbor
                        existing = get_neighbour_by_ip(ip_obj)
                        if existing:
                            # Just update the trust status
                            logger.debug(
                                f"Neighbor {sender_hostname} already exists in database, updating trust status"
                            )
                            set_neighbour_trusted(ip_obj, True)
                            logger.info(
                                f"Auto-trusting existing neighbor: {sender_hostname} at {sender_ip}"
                            )
                        else:
                            # Add to database
                            logger.debug(
                                f"Adding new trusted neighbor {sender_hostname} to database"
                            )
                            add_neighbour(new_neighbor)
                            logger.info(
                                f"Auto-trusting new neighbor: {sender_hostname} at {sender_ip}"
                            )

                        # Request password from the trusted node
                        logger.debug(
                            f"Starting thread to request password from {sender_hostname}"
                        )
                        request_password_thread = threading.Thread(
                            target=request_password_from_neighbor,
                            args=(new_neighbor if not existing else existing,),
                            daemon=True,
                        )
                        request_password_thread.start()

                        flash(
                            f"Automatically trusted neighbor {sender_hostname} ({sender_ip})",
                            "success",
                        )
                        return True

                except ValueError:
                    logger.error(f"Invalid IP address in trust request: {sender_ip}")
                    return False

        elif message_type == "password_request":
            # Handle password request from a trusted node without a password
            sender_ip = message.get("sender_ip")
            logger.debug(f"Received password request from {sender_ip}")

            if sender_ip:
                try:
                    ip_obj = ip_address(sender_ip)

                    # Only send password if we have one and the requestor is trusted
                    neighbor = get_neighbour_by_ip(ip_obj)
                    if neighbor:
                        logger.debug(
                            f"Found neighbor record for {sender_ip}, trusted: {neighbor.trusted}"
                        )

                    if neighbor and neighbor.trusted and is_password_set():
                        logger.info(
                            f"Sending password hash to trusted neighbor: {neighbor.name} ({ip_obj})"
                        )
                        send_password_to_neighbor(neighbor)
                        logger.info(
                            f"Sent password hash to trusted neighbor: {neighbor.name} ({ip_obj})"
                        )
                        return True
                    else:
                        reasons: list[str] = []
                        if not neighbor:
                            reasons.append("neighbor not found")
                        elif not neighbor.trusted:
                            reasons.append("neighbor not trusted")
                        elif not is_password_set():
                            reasons.append("no password set")

                        logger.warning(
                            f"Rejected password request from {sender_ip}: {', '.join(reasons)}"
                        )
                except ValueError:
                    logger.error(f"Invalid IP address in password request: {sender_ip}")
                    return False

        elif message_type == "password_set":
            # Handle receiving a password to set
            sender_ip = message.get("sender_ip")
            password_hash = message.get("password_hash")
            logger.debug(f"Received password_set message from {sender_ip}")

            if sender_ip and password_hash:
                try:
                    ip_obj = ip_address(sender_ip)

                    # Only accept password from trusted nodes when we don't have one
                    neighbor = get_neighbour_by_ip(ip_obj)

                    if neighbor:
                        logger.debug(
                            f"Found neighbor record for {sender_ip}, trusted: {neighbor.trusted}"
                        )

                    if neighbor and neighbor.trusted and not is_password_set():
                        # Set our password using the received hash
                        logger.info(
                            f"Setting password from trusted neighbor: {neighbor.name} ({ip_obj})"
                        )
                        set_password_from_hash(password_hash)
                        logger.info(
                            f"Set management password from trusted neighbor: {neighbor.name} ({ip_obj})"
                        )

                        # Auto-authenticate since we now have a password
                        logger.debug("Auto-authenticating session with new password")
                        session["authenticated"] = True

                        flash(
                            f"Management password set from trusted neighbor {neighbor.name} ({ip_obj})",
                            "success",
                        )
                        return True
                    else:
                        reasons = []
                        if not neighbor:
                            reasons.append("neighbor not found")
                        elif not neighbor.trusted:
                            reasons.append("neighbor not trusted")
                        elif is_password_set():
                            reasons.append("password already set")

                        logger.warning(
                            f"Rejected password set from {sender_ip}: {', '.join(reasons)}"
                        )
                except ValueError:
                    logger.error(
                        f"Invalid IP address in password set message: {sender_ip}"
                    )
                    return False
        else:
            logger.debug(f"Unhandled message type: {message_type}")

        return False
    except Exception as e:
        logger.error(f"Error handling secure message: {e}")
        return False


# Add a function to join a cluster in a background thread
def join_cluster_thread(join_command: str) -> None:
    """Join a cluster in a background thread"""
    global cluster_status
    logger.info(f"Starting cluster join process with command: {join_command}")

    try:
        logger.debug("Executing join_microk8s_cluster")
        success = join_microk8s_cluster(join_command)
        logger.debug(f"join_microk8s_cluster result: {success}")

        with cluster_status_lock:
            if success:
                cluster_status = "Successfully joined the cluster"
                logger.info("Successfully joined the Kubernetes cluster")
            else:
                cluster_status = "Failed to join the cluster"
                logger.error("Failed to join the Kubernetes cluster")
    except Exception as e:
        logger.error(f"Error joining cluster: {e}")
        with cluster_status_lock:
            cluster_status = f"Error joining cluster: {str(e)}"


# Add a function to create a cluster in a background thread
def create_cluster_thread() -> None:
    """Create a cluster in a background thread"""
    global cluster_status
    logger.info("Starting cluster creation process")

    try:
        with cluster_status_lock:
            cluster_status = "Creating cluster..."
            logger.debug(f"Updated cluster status: {cluster_status}")

        logger.debug("Executing build_microk8s_cluster")
        success = build_microk8s_cluster()
        logger.debug(f"build_microk8s_cluster result: {success}")

        with cluster_status_lock:
            if success:
                cluster_status = "Successfully created the cluster"
                logger.info("Successfully created the Kubernetes cluster")
            else:
                cluster_status = "Failed to create the cluster"
                logger.error("Failed to create the Kubernetes cluster")
    except Exception as e:
        logger.error(f"Error creating cluster: {e}")
        with cluster_status_lock:
            cluster_status = f"Error creating cluster: {str(e)}"


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
def trust_neighbor(ip: str) -> Response:
    try:
        # Convert string to IP address
        neighbor_ip = ip_address(ip)

        # Trust the neighbor locally
        if set_neighbour_trusted(neighbor_ip, True):
            flash(f"Neighbor {ip} is now trusted!", "success")

            # Send trust request to the neighbor
            neighbor = get_neighbour_by_ip(neighbor_ip)
            if neighbor:
                success = send_trust_request(neighbor_ip)
                if success:
                    flash(f"Sent trust request to {ip}", "info")
                else:
                    flash(f"Failed to send trust request to {ip}", "warning")
        else:
            flash(f"Neighbor {ip} not found.", "error")

    except ValueError:
        flash("Invalid IP address", "error")
    except Exception as e:
        logger.error(f"Error trusting neighbor: {e}")
        flash(f"Error: {str(e)}", "error")

    return redirect(url_for("dashboard"))


@app.route("/neighbors/<ip>/untrust", methods=["POST"])
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


@app.route("/dashboard")
@login_required
def dashboard():
    """Dashboard view with system information and neighbors"""
    # Get active neighbors from memory cache
    with neighbors_lock:
        active_neighbors_list: list[dict[str, str | int | datetime]] = [
            {
                "hostname": data.get("hostname", "unknown"),
                "ip": str(data["ip"]),
                "port": data["port"],
                "last_seen": data["last_seen"],
            }
            for data in neighbors.values()
        ]

    # Get all neighbors from the database
    try:

        db_neighbors = get_all_neighbours()
        trusted_neighbors: list[Neighbour] = get_trusted_neighbours()
        trusted_count = len(trusted_neighbors) if trusted_neighbors else 0
    except (ImportError, AttributeError):
        db_neighbors = []
        trusted_count = 0

    # Get current cluster status
    with cluster_status_lock:
        current_cluster_status = cluster_status

    return render_template(
        "dashboard.html",
        hostname=LOCAL_HOSTNAME,
        ip=str(LOCAL_IP),
        port=args.port,
        active_neighbors=active_neighbors_list,
        neighbor_count=len(active_neighbors_list),
        db_neighbors=db_neighbors,
        trusted_count=trusted_count,
        cluster_status=current_cluster_status,
    )


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


# Add a route to create a cluster
@app.route("/create-cluster", methods=["POST"])
@login_required
def create_cluster() -> Response:
    """Create a Kubernetes cluster with trusted neighbors"""
    try:
        # Get trusted neighbors
        trusted_neighbors = get_trusted_neighbours()

        if len(trusted_neighbors) < 2:
            flash(
                "At least 2 trusted neighbors are required to create a cluster.",
                "error",
            )
            return redirect(url_for("dashboard"))

        # Start cluster creation in a background thread
        cluster_thread = threading.Thread(
            target=create_cluster_thread,
            daemon=True,
        )
        cluster_thread.start()

        flash("Cluster creation started. This may take a few minutes.", "info")
    except Exception as e:
        logger.error(f"Error starting cluster creation: {e}")
        flash(f"Error starting cluster creation: {str(e)}", "error")

    return redirect(url_for("dashboard"))


# Add an endpoint to receive secure messages
@app.route("/api/secure-message", methods=["POST"])
def api_secure_message() -> Response | tuple[Response, int]:
    """Handle secure messages from other nodes"""

    # No need to be authenticated as the authentication is done at the message level

    try:
        logger.debug(f"Received secure message request {request}")
        encrypted_payload = request.json
        if not encrypted_payload:
            logger.error(f"Received message {request} is empty or not JSON")
            return jsonify({"error": "Invalid message format"}), 400

        # Extract encrypted message parts
        nonce = encrypted_payload.get("nonce")
        ciphertext = encrypted_payload.get("ciphertext")
        sender_key = encrypted_payload.get("sender_key")

        if not all([nonce, ciphertext, sender_key]):
            logger.error("Missing required encryption fields in message")
            return jsonify({"error": "Invalid encrypted message format"}), 400

        # Decrypt the message first

        decrypted_message = receive_secure_message(
            sender_key, nonce, ciphertext, bypass_trust_check=not is_password_set()
        )

        if not decrypted_message:
            logger.error("Failed to decrypt message")
            return jsonify({"error": "Message decryption failed"}), 400

        # Now process the decrypted message
        logger.debug(f"Decrypted message: {decrypted_message}")
        success = handle_secure_message(decrypted_message)
        if success:
            return jsonify({"status": "success"})
        else:
            logger.error(f"Failed to process decrypted message")
            return jsonify({"error": "Failed to process message"}), 400
    except Exception as e:
        logger.error(f"Error processing secure message: {e}")
        return jsonify({"error": str(e)}), 500


def request_password_from_neighbor(neighbor: Neighbour) -> None:
    """Request the management password from a trusted neighbor"""
    logger.info(
        f"Requesting password from neighbor: {neighbor.name} ({neighbor.ip_address})"
    )

    try:
        # Don't request if we already have a password
        if is_password_set():
            logger.debug(
                "Not requesting password from neighbor: we already have one set"
            )
            return

        # Create the password request message
        message = {
            "type": "password_request",
            "sender_ip": str(LOCAL_IP),
            "sender_hostname": LOCAL_HOSTNAME,
            "timestamp": datetime.now().isoformat(),
        }
        logger.debug(f"Created password request message: {message}")

        # Send the message
        logger.info(
            f"Sending password request to trusted neighbor: {neighbor.name} ({neighbor.ip_address})"
        )
        response = send_secure_message(neighbor, message)
        logger.debug(f"Password request response: {response}")

        if not response:
            logger.warning(
                f"Failed to request password from {neighbor.name} ({neighbor.ip_address})"
            )
    except Exception as e:
        logger.error(f"Error requesting password from neighbor: {e}")


def send_password_to_neighbor(neighbor: Neighbour) -> bool:
    """Send our management password to a trusted neighbor that requested it"""
    logger.info(
        f"Preparing to send password to neighbor: {neighbor.name} ({neighbor.ip_address})"
    )

    try:
        # Check that we have a password to send
        if not is_password_set():
            logger.warning("Cannot send password: no password is set")
            return False

        # Read the password hash - don't decrypt it
        with open(PASSWORD_FILE, "rb") as f:
            password_hash = f.read()
        logger.debug(f"Read password hash of {len(password_hash)} bytes")

        # Encode as base64 for transmission
        password_hash_b64 = base64.b64encode(password_hash).decode("ascii")
        logger.debug(
            f"Encoded password hash for transmission ({len(password_hash_b64)} chars)"
        )

        # Create the password set message
        message = {
            "type": "password_set",
            "sender_ip": str(LOCAL_IP),
            "sender_hostname": LOCAL_HOSTNAME,
            "password_hash": password_hash_b64,
            "timestamp": datetime.now().isoformat(),
        }
        logger.debug("Created password_set message (hash redacted)")

        # Send the message
        logger.info(f"Sending password hash to trusted neighbor: {neighbor.name}")
        response = send_secure_message(neighbor, message)
        logger.debug(f"Password set response received: {response is not None}")
        return response is not None
    except Exception as e:
        logger.error(f"Error sending password to neighbor: {e}")
        return False


def set_password_from_hash(password_hash_b64: str) -> bool:
    """Set the password from a received hash"""
    logger.info("Setting password from received hash")

    try:
        # Decode from base64
        password_hash = base64.b64decode(password_hash_b64)
        logger.debug(f"Decoded password hash ({len(password_hash)} bytes)")

        # Write the hash directly to the password file
        with open(PASSWORD_FILE, "wb") as f:
            f.write(password_hash)
        logger.debug(f"Wrote password hash to {PASSWORD_FILE}")

        os.chmod(PASSWORD_FILE, 0o600)  # Secure the password file
        logger.info("Successfully set password from trusted neighbor")
        return True
    except Exception as e:
        logger.error(f"Error setting password from hash: {e}")
        return False


def send_trust_request(neighbor_ip: IPv4Address | IPv6Address) -> bool:
    """
    Send a request to establish bidirectional trust with a neighbor

    Args:
        neighbor_ip: The IP address of the neighbor to request trust from

    Returns:
        True if the request was sent successfully, False otherwise
    """
    logger.info(f"Preparing to send trust request to neighbor: {neighbor_ip}")

    try:
        # Get neighbor from database
        neighbor = get_neighbour_by_ip(neighbor_ip)
        if not neighbor:
            logger.error(f"Cannot send trust request: neighbor {neighbor_ip} not found")
            return False

        logger.debug(f"Found neighbor record: {neighbor.name} ({neighbor.ip_address})")

        # Create the trust request message
        message = {
            "type": "trust_request",
            "sender_ip": str(LOCAL_IP),
            "sender_hostname": LOCAL_HOSTNAME,
            "sender_public_key": get_public_key_base64(),
            "timestamp": datetime.now().isoformat(),
        }
        logger.debug("Created trust_request message")

        # Send the message
        logger.debug(f"Original trust status: {neighbor.trusted}")
        # For a trust request, we need to temporarily mark the neighbor as trusted
        # to allow the secure message to be sent
        original_trust_status = neighbor.trusted
        neighbor.trusted = True
        logger.debug(f"Temporarily set trust to True for sending")

        logger.info(
            f"Sending trust request to: {neighbor.name} ({neighbor.ip_address})"
        )
        result = send_secure_message(neighbor, message)
        logger.debug(f"Trust request result: {result is not None}")

        # Restore original trust status if we didn't really trust them yet
        if not original_trust_status:
            logger.debug("Restoring original trust status")
            neighbor.trusted = original_trust_status

        return result is not None
    except Exception as e:
        logger.error(f"Error sending trust request: {e}")
        return False


def main() -> None:
    """Main function for the service."""
    # Always parse arguments
    parse_arguments()
    print(f"Specified log level {args.loglevel.upper()}")
    # Configure the root logger
    logging.basicConfig(
        level=args.loglevel.upper(),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Also configure the module logger
    logger.setLevel(args.loglevel.upper())

    # Configure Flask's logger
    flask_logger = logging.getLogger("werkzeug")
    flask_logger.setLevel(args.loglevel.upper())

    # Log that we've configured logging
    logger.info("Logging now setup at level: %s", args.loglevel.upper())

    # Test debug logging is working
    logger.debug(
        "This is a debug message that should appear if debug logging is enabled"
    )

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

        # Check if debug mode is requested
        debug_mode = args.loglevel.lower() == "debug"

        # If debug mode is enabled, log this
        if debug_mode:
            logger.info("Debug mode enabled for web server")

        # Start the web server with debug mode matching loglevel
        app.run(host="0.0.0.0", port=args.port, debug=debug_mode)

    except KeyboardInterrupt:
        logger.info("Auto MicroK8s Cluster service stopped.")
    except Exception as e:
        logger.error(f"Service encountered an error: {e}")


if __name__ == "__main__":
    main()
else:
    # Even when imported as a module, ensure arguments are parsed
    # This runs when the module is imported, ensuring args are available
    parse_arguments()
