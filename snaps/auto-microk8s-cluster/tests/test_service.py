import json
import socket
from collections.abc import Generator
from datetime import datetime, timedelta
from ipaddress import ip_address
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest
from flask.testing import FlaskClient

from auto_microk8s_cluster.neighbours import Neighbour
from auto_microk8s_cluster.service import (
    LOCAL_HOSTNAME,
    LOCAL_IP,
    app,
    cleanup_neighbors,
    get_hostname,
    get_local_ip,
    listen_for_broadcasts,
    neighbors,
    neighbors_lock,
    send_discovery_broadcast,
)


@pytest.fixture
def client() -> Generator[FlaskClient, None, None]:
    """Create a test client for the Flask app"""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def reset_neighbors() -> Generator[None, None, None]:
    """Reset the neighbors dict before and after each test"""
    with neighbors_lock:
        neighbors.clear()
    yield
    with neighbors_lock:
        neighbors.clear()


class TestUtilityFunctions:
    """Tests for utility functions in the service module"""

    @patch("socket.socket")
    def test_get_local_ip_success(self, mock_socket: MagicMock) -> None:
        """Test getting local IP when connection succeeds"""
        # Setup the mock
        mock_socket_instance = MagicMock()
        mock_socket.return_value = mock_socket_instance
        mock_socket_instance.getsockname.return_value = ("192.168.1.10", 12345)

        # Call the function
        result = get_local_ip()

        # Assertions
        assert result == ip_address("192.168.1.10")
        mock_socket_instance.connect.assert_called_once_with(("google.com", 80))

    @patch("socket.socket")
    def test_get_local_ip_failure(self, mock_socket: MagicMock) -> None:
        """Test getting local IP when connection fails"""
        # Setup the mock to raise exception
        mock_socket_instance = MagicMock()
        mock_socket.return_value = mock_socket_instance
        mock_socket_instance.connect.side_effect = Exception("Connection failed")

        # Call the function
        result = get_local_ip()

        # Should return localhost on failure
        assert result == ip_address("127.0.0.1")

    @patch("socket.gethostname")
    def test_get_hostname_success(self, mock_gethostname: MagicMock) -> None:
        """Test getting hostname when it succeeds"""
        mock_gethostname.return_value = "test-host"

        result = get_hostname()

        assert result == "test-host"

    @patch("socket.gethostname")
    def test_get_hostname_failure(self, mock_gethostname: MagicMock) -> None:
        """Test getting hostname when it fails"""
        mock_gethostname.side_effect = Exception("Hostname lookup failed")

        result = get_hostname()

        assert result == "unknown-host"


class TestBroadcastAndDiscovery:
    """Tests for broadcast and discovery functions"""

    @patch("auto_microk8s_cluster.service.get_public_key_base64")
    @patch("socket.socket")
    @patch(
        "auto_microk8s_cluster.service.time.sleep", side_effect=InterruptedError
    )  # Stop the infinite loop
    @patch("auto_microk8s_cluster.service.args")
    def test_send_discovery_broadcast(
        self,
        mock_args: MagicMock,
        mock_sleep: MagicMock,
        mock_socket: MagicMock,
        mock_get_key: MagicMock,
    ) -> None:
        """Test sending discovery broadcasts"""
        # Setup mocks
        mock_args.port = 8800
        mock_args.discovery_port = 8801
        mock_socket_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_socket_instance
        mock_get_key.return_value = "test-public-key"

        # Run function (will raise InterruptedError to break the loop)
        with pytest.raises(InterruptedError):
            send_discovery_broadcast()

        # Verify broadcasting
        mock_socket_instance.setsockopt.assert_called_once_with(
            socket.SOL_SOCKET, socket.SO_BROADCAST, 1
        )
        mock_socket_instance.sendto.assert_called()

        # Get the broadcast message
        call_args = mock_socket_instance.sendto.call_args[0]
        message = json.loads(call_args[0].decode())

        # Verify message contents
        assert message["ip"] == str(LOCAL_IP)
        assert message["port"] == 8800
        assert message["hostname"] == LOCAL_HOSTNAME
        assert message["public_key"] == "test-public-key"
        assert "timestamp" in message

    @patch("auto_microk8s_cluster.service.add_neighbour")
    @patch("auto_microk8s_cluster.service.get_neighbour_by_ip")
    @patch("socket.socket")
    @patch("auto_microk8s_cluster.service.args")
    @patch("auto_microk8s_cluster.service.LOCAL_IP", ip_address("192.168.1.5"))
    def test_listen_for_broadcasts_new_neighbor(
        self,
        mock_local_ip: MagicMock,
        mock_args: MagicMock,
        mock_socket: MagicMock,
        mock_get_neighbour: MagicMock,
        mock_add_neighbour: MagicMock,
        reset_neighbors: None,
    ) -> None:
        """Test listening for broadcasts from a new neighbor"""
        # Setup mocks
        mock_args.discovery_port = 8801
        mock_args.port = 8800
        mock_socket_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_socket_instance

        # Create test timestamp
        test_timestamp = datetime.now().isoformat()

        # Create a custom exception that won't be caught by except Exception
        class TestStopSignal(BaseException):
            pass

        # Create the test data tuple that recvfrom should return
        test_data = (
            json.dumps(
                {
                    "ip": "192.168.1.100",
                    "port": 8800,
                    "hostname": "test-neighbor",
                    "public_key": "neighbor-public-key",
                    "timestamp": test_timestamp,
                }
            ).encode(),
            ("192.168.1.100", 8801),
        )

        # Setup mock to return data once, then raise exception
        mock_recvfrom = MagicMock()
        mock_recvfrom.side_effect = [test_data, TestStopSignal("Stop the test")]
        mock_socket_instance.recvfrom = mock_recvfrom

        # Mock that we don't know this neighbor yet
        mock_get_neighbour.return_value = None

        # Run function - should break out on BaseException
        with pytest.raises(TestStopSignal):
            listen_for_broadcasts()

        # Verify socket was set up correctly
        mock_socket_instance.setsockopt.assert_called_once_with(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
        )
        mock_socket_instance.bind.assert_called_once_with(
            ("", mock_args.discovery_port)
        )

        # Verify recvfrom was called
        mock_recvfrom.assert_called()

        # Verify neighbor was added
        mock_add_neighbour.assert_called_once()
        neighbor_arg = mock_add_neighbour.call_args[0][0]
        assert isinstance(neighbor_arg, Neighbour)
        assert neighbor_arg.name == "test-neighbor"
        assert str(neighbor_arg.ip_address) == "192.168.1.100"
        assert neighbor_arg.public_key == "neighbor-public-key"
        assert not neighbor_arg.trusted  # Should default to untrusted

        # Verify in-memory cache update
        with neighbors_lock:
            assert ip_address("192.168.1.100") in neighbors
            assert neighbors[ip_address("192.168.1.100")]["hostname"] == "test-neighbor"
            assert neighbors[ip_address("192.168.1.100")]["port"] == 8800
            assert (
                neighbors[ip_address("192.168.1.100")]["public_key"]
                == "neighbor-public-key"
            )

    @patch("auto_microk8s_cluster.service.time.sleep", side_effect=InterruptedError)
    def test_cleanup_neighbors(
        self, mock_sleep: MagicMock, reset_neighbors: None
    ) -> None:
        """Test cleaning up stale neighbors"""
        # Add some neighbors
        with neighbors_lock:
            # Fresh neighbor
            neighbors[ip_address("192.168.1.100")] = {
                "ip": ip_address("192.168.1.100"),
                "hostname": "fresh-neighbor",
                "port": 8800,
                "public_key": "key1",
                "last_seen": datetime.now(),
            }

            # Stale neighbor
            neighbors[ip_address("192.168.1.200")] = {
                "ip": ip_address("192.168.1.200"),
                "hostname": "stale-neighbor",
                "port": 8800,
                "public_key": "key2",
                "last_seen": datetime.now()
                - timedelta(seconds=100),  # Older than NODE_TIMEOUT
            }

        # Run the cleanup function
        with pytest.raises(InterruptedError):
            cleanup_neighbors()

        # Verify stale neighbor was removed
        with neighbors_lock:
            assert (
                ip_address("192.168.1.100") in neighbors
            )  # Fresh neighbor still there
            assert (
                ip_address("192.168.1.200") not in neighbors
            )  # Stale neighbor removed


class TestFlaskAPI:
    """Tests for the Flask API endpoints"""

    def test_home_endpoint(self, client: FlaskClient) -> None:
        """Test the home endpoint returns correct information"""
        response = client.get("/")
        data = json.loads(response.data)

        assert response.status_code == 200
        assert data["service"] == "Auto MicroK8s Cluster"
        assert data["status"] == "running"
        assert data["hostname"] == LOCAL_HOSTNAME
        assert data["ip"] == str(LOCAL_IP)

    def test_list_neighbors_endpoint(
        self, client: FlaskClient, reset_neighbors: None
    ) -> None:
        """Test the neighbors listing endpoint"""
        # Add some test neighbors
        with neighbors_lock:
            neighbors[ip_address("192.168.1.100")] = {
                "ip": ip_address("192.168.1.100"),
                "hostname": "test-neighbor-1",
                "port": 8800,
                "public_key": "test-key-1",
                "last_seen": datetime.now(),
            }
            neighbors[ip_address("192.168.1.200")] = {
                "ip": ip_address("192.168.1.200"),
                "hostname": "test-neighbor-2",
                "port": 8800,
                "public_key": "test-key-2",
                "last_seen": datetime.now(),
            }

        # Make the API call
        response = client.get("/neighbors")
        data = json.loads(response.data)

        # Verify response
        assert response.status_code == 200
        assert data["count"] == 2
        assert "192.168.1.100" in data["neighbors"]
        assert "192.168.1.200" in data["neighbors"]
        assert data["neighbors"]["192.168.1.100"]["hostname"] == "test-neighbor-1"
        assert data["neighbors"]["192.168.1.200"]["hostname"] == "test-neighbor-2"
        assert data["neighbors"]["192.168.1.100"]["has_public_key"] is True

    @patch("auto_microk8s_cluster.service.set_neighbour_trusted")
    def test_trust_neighbor_success(
        self, mock_set_trusted: MagicMock, client: FlaskClient
    ) -> None:
        """Test trusting a neighbor when it succeeds"""
        # Setup mock
        mock_set_trusted.return_value = True  # Neighbor exists and was updated

        # Make the API call
        response = client.post("/neighbors/192.168.1.100/trust")
        data = json.loads(response.data)

        # Verify response
        assert response.status_code == 200
        assert data["success"] is True
        assert "is now trusted" in data["message"]
        mock_set_trusted.assert_called_once_with(ip_address("192.168.1.100"), True)

    @patch("auto_microk8s_cluster.service.set_neighbour_trusted")
    def test_trust_neighbor_not_found(
        self, mock_set_trusted: MagicMock, client: FlaskClient
    ) -> None:
        """Test trusting a neighbor that doesn't exist"""
        # Setup mock
        mock_set_trusted.return_value = False  # Neighbor doesn't exist

        # Make the API call
        response = client.post("/neighbors/192.168.1.100/trust")
        data = json.loads(response.data)

        # Verify response
        assert response.status_code == 404
        assert data["success"] is False
        assert "not found" in data["message"]

    def test_trust_neighbor_invalid_ip(self, client: FlaskClient) -> None:
        """Test trusting a neighbor with an invalid IP address"""
        # Make the API call with invalid IP
        response = client.post("/neighbors/invalid-ip/trust")
        data = json.loads(response.data)

        # Verify response
        assert response.status_code == 400
        assert data["success"] is False
        assert "Invalid IP address" in data["message"]


@pytest.mark.parametrize("setup_result", [True, False])
@patch("auto_microk8s_cluster.service.app.run")
@patch("auto_microk8s_cluster.service.threading.Thread")
@patch("auto_microk8s_cluster.service.setup_system")
def test_main_function(
    mock_setup: MagicMock,
    mock_thread: MagicMock,
    mock_run: MagicMock,
    setup_result: bool,
) -> None:
    """Test the main function with successful and unsuccessful setup"""
    # Setup mock
    mock_setup.return_value = setup_result
    mock_thread_instances = [MagicMock(), MagicMock(), MagicMock()]
    mock_thread.side_effect = mock_thread_instances

    # Call main function
    from auto_microk8s_cluster.service import main

    main()

    # Verify setup was called
    mock_setup.assert_called_once()

    # Verify threads were started
    assert mock_thread.call_count == 3
    for thread in mock_thread_instances:
        thread.start.assert_called_once()

    # Verify Flask app was started
    mock_run.assert_called_once_with(host="0.0.0.0", port=mock.ANY, debug=False)


if __name__ == "__main__":
    pytest.main()
