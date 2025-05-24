import argparse
import json
import logging
import socket
import threading
import time
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any

import requests_unixsocket  # New import
from flask import Flask, jsonify

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

args = parser.parse_args()

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=args.loglevel.upper())
logger.info("Logging now setup.")

# Create Flask app
app = Flask(__name__)


# Store discovered neighbors
neighbors: dict[IPv4Address | IPv6Address, dict[str, Any]] = {}
neighbors_lock = threading.Lock()


# Get local IP address
def get_local_ip():
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


LOCAL_IP = get_local_ip()
BROADCAST_INTERVAL = 30  # seconds
NODE_TIMEOUT = 90  # seconds


# Discovery service
def send_discovery_broadcast():
    """Send periodic UDP broadcasts to announce this service's presence"""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while True:
            try:
                message = json.dumps(
                    {
                        "ip": str(LOCAL_IP),  # Convert to string for JSON
                        "port": args.port,
                        "timestamp": datetime.now().isoformat(),
                    }
                )
                sock.sendto(message.encode(), ("<broadcast>", args.discovery_port))
                logger.debug(f"Sent discovery broadcast from {LOCAL_IP}:{args.port}")
            except Exception as e:
                logger.error(f"Error sending discovery broadcast: {e}")

            time.sleep(BROADCAST_INTERVAL)


def listen_for_broadcasts():
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
                with neighbors_lock:
                    neighbors[sender_ip] = {
                        "ip": sender_ip,
                        "port": info.get("port", args.port),
                        "last_seen": datetime.now(),
                    }
                logger.info(f"Discovered neighbor at {sender_ip}")
            except Exception as e:
                logger.error(f"Error receiving discovery broadcast: {e}")


def cleanup_neighbors():
    """Remove stale neighbors"""
    while True:
        time.sleep(10)
        stale = [
            ip
            # type: list[ip_address]
            for ip, data in neighbors.items()
            if datetime.now() - data["last_seen"] > timedelta(seconds=NODE_TIMEOUT)
        ]
        for ip in stale:
            logger.info(f"Removing stale neighbor: {ip}")
            del neighbors[ip]


# Web Service Routes
@app.route("/")
def home():
    return jsonify(
        {
            "service": "Auto MicroK8s Cluster",
            "status": "running",
            "ip": str(LOCAL_IP),  # Convert to string for JSON
            "port": args.port,
        }
    )


@app.route("/neighbors")
def list_neighbors():
    with neighbors_lock:
        active_neighbors: dict[str, dict[str, str | int]] = {
            str(ip): {  # Convert ip_address key to string for JSON
                "ip": str(data["ip"]),  # Convert ip_address to string for JSON
                "port": data["port"],
                "last_seen": data["last_seen"].isoformat(),
            }
            for ip, data in neighbors.items()
        }

    return jsonify(
        {
            "this_node": {"ip": str(LOCAL_IP), "port": args.port},
            "neighbors": active_neighbors,
            "count": len(active_neighbors),
        }
    )


# Function to interact with snapd API using requests-unixsocket
def connect_to_snapd(
    method: str, endpoint: str, data: dict[str, Any] | None = None
) -> dict[str, Any]:
    """
    Connect to the snapd API via the UNIX socket using requests-unixsocket.

    Args:
        method: HTTP method (GET, POST)
        endpoint: API endpoint (e.g., /v2/snaps/microk8s)
        data: Optional data for POST requests

    Returns:
        The JSON response from the API
    """
    # Create a requests-unixsocket session
    session = requests_unixsocket.Session()

    # Format the URL for Unix socket
    url = f"http+unix://%2Frun%2Fsnapd.socket{endpoint}"

    try:
        if method.upper() == "GET":
            response = session.get(url)
        elif method.upper() == "POST":
            response = session.post(url, json=data)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        return response.json()
    except Exception as e:
        logger.error(f"Error connecting to snapd API: {e}")
        return {"type": "error", "result": {"message": str(e)}}
    finally:
        session.close()


def is_microk8s_installed() -> bool:
    """Check if MicroK8s snap is installed using the snapd API."""
    try:
        response = connect_to_snapd("GET", "/v2/snaps/microk8s")

        # If the response type is "sync" and status code is 200, the snap exists
        if response.get("type") == "sync" and response.get("status-code") == 200:
            logger.info("MicroK8s snap is already installed")
            return True

        # If we get a 404, the snap is not installed
        if response.get("status-code") == 404:
            logger.info("MicroK8s snap is not installed")
            return False

        # Unexpected response
        logger.warning(f"Unexpected response checking for MicroK8s: {response}")
        return False
    except Exception as e:
        logger.error(f"Error checking if MicroK8s is installed: {e}")
        return False


def install_microk8s() -> bool:
    """Install MicroK8s snap using the snapd API."""
    try:
        logger.info("Installing MicroK8s snap...")
        data = {"action": "install", "channel": "stable"}
        response = connect_to_snapd("POST", "/v2/snaps/microk8s", data)

        # If it's an async operation, it's started successfully
        if response.get("type") == "async":
            change_id = response.get("change")
            logger.info(f"MicroK8s installation started (change ID: {change_id})")

            # Wait for the installation to complete
            while True:
                change_response = connect_to_snapd("GET", f"/v2/changes/{change_id}")
                status = change_response.get("result", {}).get("status")

                if status == "Done":
                    logger.info("MicroK8s installation completed successfully")
                    return True
                elif status in ["Error", "Abort"]:
                    logger.error(f"MicroK8s installation failed: {change_response}")
                    return False

                # Wait before checking again
                time.sleep(5)
        else:
            logger.error(f"Failed to start MicroK8s installation: {response}")
            return False
    except Exception as e:
        logger.error(f"Error installing MicroK8s: {e}")
        return False


def main():
    """Main function for the service."""
    logger.info(f"Auto MicroK8s Cluster service started on {LOCAL_IP}:{args.port}")

    try:
        # Check if MicroK8s is installed via snapd API
        if not is_microk8s_installed():
            logger.info("MicroK8s not found. Installing...")
            if install_microk8s():
                logger.info("MicroK8s installed successfully")
            else:
                logger.error("Failed to install MicroK8s")
        else:
            logger.info("MicroK8s is already installed")

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
    main()
