import io
from collections.abc import Generator
from datetime import datetime, timedelta
from ipaddress import IPv4Address, ip_address
from typing import Any

import pytest
from flask import flash
from flask.testing import FlaskClient
from hypothesis import given
from hypothesis import strategies as st
from lxml import etree

from auto_microk8s_cluster.neighbours import Neighbour
from auto_microk8s_cluster.service import app


@pytest.fixture
def client() -> Generator[FlaskClient, None, None]:
    """Create a test client for the Flask app"""
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False  # Disable CSRF for testing
    with app.test_client() as client:
        yield client


@pytest.fixture
def authenticated_client(client: FlaskClient) -> FlaskClient:
    """Create an authenticated test client for the Flask app"""
    with client.session_transaction() as session:
        session["authenticated"] = True
    return client


def validate_xhtml(content: bytes) -> list[str]:
    """
    Validate XHTML5 content and return any errors

    Args:
        content: The XHTML content to validate as bytes

    Returns:
        List of error messages, empty if valid
    """
    parser = etree.XMLParser(dtd_validation=False, no_network=True)
    errors: list[str] = []

    try:
        # Try to parse the document
        etree.parse(io.BytesIO(content), parser)
    except etree.XMLSyntaxError as e:
        errors.append(str(e))
        # Get detailed errors from the error log
        for error in parser.error_log:
            errors.append(f"Line {error.line}: {error.message}")

    return errors


# Define hypothesis strategies for generating test data
ip_addresses = st.builds(
    lambda ip: IPv4Address(ip), st.integers(min_value=0, max_value=2**32 - 1)  # type: ignore
)

hostnames = st.one_of(
    st.text(
        alphabet=st.characters(whitelist_categories=["Lu", "Ll", "Nd"]),
        min_size=1,
        max_size=50,
    ),
    # Include some special character test cases
    st.sampled_from(
        [
            "host-name_1",
            "test.example.com",
            "node-01",
            "<script>alert('XSS')</script>",
            "host & name",
            "host with spaces",
            "très-spécial",
            "정보기술",
        ]
    ),
)

# Fix the timestamp strategy type annotation
timestamps = st.builds(
    lambda days, hours, mins: datetime.now()  # type: ignore
    - timedelta(days=days, hours=hours, minutes=mins),  # type: ignore
    st.integers(min_value=0, max_value=10),  # days
    st.integers(min_value=0, max_value=23),  # hours
    st.integers(min_value=0, max_value=59),  # minutes
)

ports = st.integers(min_value=1024, max_value=65535)

# Generate flash messages with potentially problematic content
flash_messages = st.one_of(
    st.text(min_size=1, max_size=200),
    # Include potentially problematic HTML content
    st.sampled_from(
        [
            "Success!",
            "<script>alert('XSS')</script>",
            "Password & username don't match",
            "Error in I/O operation",
            """Multi-line
        error message
        with special chars: <>&"'""",
        ]
    ),
)

# Strategy for generating neighbour data with proper type annotations
from typing import TypedDict


class NeighbourDict(TypedDict):
    hostname: str
    ip: IPv4Address
    port: int
    last_seen: datetime
    has_public_key: bool


def make_neighbour_dict(
    hostname: str, ip: IPv4Address, port: int, timestamp: datetime
) -> NeighbourDict:
    return NeighbourDict(
        hostname=hostname,
        ip=ip,
        port=port,
        last_seen=timestamp,
        has_public_key=True,
    )


neighbours_strategy = st.builds(
    make_neighbour_dict,
    hostnames,
    ip_addresses,
    ports,
    timestamps,
)

# Strategy for generating database neighbours with proper type annotations
db_neighbours_strategy = st.builds(
    lambda name, ip, trusted: Neighbour(  # type: ignore
        name=name, ip_address=ip, public_key="dummy-key", trusted=trusted  # type: ignore
    ),  # type: ignore
    hostnames,
    ip_addresses,
    st.booleans(),
)


# Existing tests
def test_setup_password_page_is_valid_xhtml(client: FlaskClient) -> None:
    """Test that the setup password page renders valid XHTML5"""
    # Mock password check so we can access setup page
    with pytest.MonkeyPatch().context() as mp:
        mp.setattr("auto_microk8s_cluster.service.is_password_set", lambda: False)

        # Request the page
        response = client.get("/setup-password")

        # Check content type
        assert (
            response.headers["Content-Type"] == "application/xhtml+xml; charset=utf-8"
        )

        # Validate the content
        errors = validate_xhtml(response.data)
        if errors:
            pytest.fail(f"XHTML validation errors: {errors}")


# New hypothesis-based tests with fixed type annotations
@given(error_message=flash_messages)
def test_setup_password_with_error_is_valid_xhtml(
    client: FlaskClient, error_message: str
) -> None:
    """Test that the setup password page renders valid XHTML5 with various error messages"""
    with pytest.MonkeyPatch().context() as mp:
        mp.setattr("auto_microk8s_cluster.service.is_password_set", lambda: False)

        # Mock the form submission with error
        mp.setattr("auto_microk8s_cluster.service.set_password", lambda password: False)  # type: ignore

        # Submit the form with mismatched passwords to trigger error
        _response = client.post(
            "/setup-password",
            data={"password": "test", "confirm_password": "different"},
            follow_redirects=True,
        )

        # Then render with custom error message
        with app.test_request_context():
            rendered = app.jinja_env.get_template("setup_password.html").render(
                error=error_message
            )

        # Convert to bytes for validation
        rendered_bytes = rendered.encode("utf-8")

        # Validate the content
        errors = validate_xhtml(rendered_bytes)
        if errors:
            pytest.fail(
                f"XHTML validation errors with message '{error_message}': {errors}"
            )


@given(error_message=flash_messages)
def test_login_with_error_is_valid_xhtml(
    client: FlaskClient, error_message: str
) -> None:
    """Test that the login page renders valid XHTML5 with various error messages"""
    with pytest.MonkeyPatch().context() as mp:
        mp.setattr("auto_microk8s_cluster.service.is_password_set", lambda: True)

        # Render the template with various error messages
        with app.test_request_context():
            rendered = app.jinja_env.get_template("login.html").render(
                error=error_message
            )

        # Convert to bytes for validation
        rendered_bytes = rendered.encode("utf-8")

        # Validate the content
        errors = validate_xhtml(rendered_bytes)
        if errors:
            pytest.fail(
                f"XHTML validation errors with message '{error_message}': {errors}"
            )


@given(
    active_neighbors=st.lists(neighbours_strategy, min_size=0, max_size=10),
    db_neighbors=st.lists(db_neighbours_strategy, min_size=0, max_size=10),
    hostname=hostnames,
    ip=ip_addresses,
    port=ports,
)
def test_dashboard_with_various_data_is_valid_xhtml(
    authenticated_client: FlaskClient,
    active_neighbors: list[dict[str, Any]],
    db_neighbors: list[Neighbour],
    hostname: str,
    ip: IPv4Address,
    port: int,
) -> None:
    """Test that the dashboard renders valid XHTML5 with various data"""
    with pytest.MonkeyPatch().context() as mp:
        mp.setattr("auto_microk8s_cluster.service.is_password_set", lambda: True)
        mp.setattr(
            "auto_microk8s_cluster.service.get_all_neighbours", lambda: db_neighbors
        )

        # Replace global variables with our test data
        mp.setattr("auto_microk8s_cluster.service.LOCAL_HOSTNAME", hostname)
        mp.setattr("auto_microk8s_cluster.service.LOCAL_IP", ip)
        mp.setattr("auto_microk8s_cluster.service.args.port", port)

        # Mock the neighbors data
        test_neighbors: dict[IPv4Address, dict[str, Any]] = {}
        for neighbor in active_neighbors:
            test_ip = ip_address(neighbor["ip"])
            test_neighbors[test_ip] = {  # type: ignore
                "ip": test_ip,
                "hostname": neighbor["hostname"],
                "port": neighbor["port"],
                "last_seen": neighbor["last_seen"],
                "public_key": "test-key" if neighbor["has_public_key"] else "",
            }

        mp.setattr("auto_microk8s_cluster.service.neighbors", test_neighbors)

        # Request the dashboard
        response = authenticated_client.get("/dashboard")

        # Check content type
        assert (
            response.headers["Content-Type"] == "application/xhtml+xml; charset=utf-8"
        )

        # Validate the content
        errors = validate_xhtml(response.data)
        if errors:
            # For debugging purposes, print some info about the data that caused the error
            print(f"\nHost: {hostname}, IP: {ip}, Port: {port}")
            print(f"Active neighbors: {len(active_neighbors)}")
            print(f"DB neighbors: {len(db_neighbors)}")
            for i, n in enumerate(active_neighbors):
                print(f"  Neighbor {i}: {n['hostname']} ({n['ip']})")
            pytest.fail(f"XHTML validation errors: {errors}")


@given(
    message=flash_messages,
    category=st.sampled_from(["success", "error", "info", "warning"]),
)
def test_flash_messages_render_valid_xhtml(
    authenticated_client: FlaskClient, message: str, category: str
) -> None:
    """Test that flash messages render valid XHTML5"""
    with app.test_request_context():
        # Set up the flash message
        flash(message, category)

        # Render a simple template that would display the flash message
        rendered = app.jinja_env.get_template("base.html").render(
            session={"authenticated": True}
        )

        # Convert to bytes for validation
        rendered_bytes = rendered.encode("utf-8")

        # Validate the content
        errors = validate_xhtml(rendered_bytes)
        if errors:
            pytest.fail(
                f"XHTML validation errors with flash message '{message}' ({category}): {errors}"
            )


@given(hostname=hostnames, ip=ip_addresses)
def test_trust_neighbor_redirect_is_valid(
    authenticated_client: FlaskClient, hostname: str, ip: IPv4Address
) -> None:
    """Test that trusting a neighbor with various IPs redirects properly"""
    with pytest.MonkeyPatch().context() as mp:
        # Fix the lambda syntax error
        mp.setattr(
            "auto_microk8s_cluster.service.set_neighbour_trusted",
            lambda ip_addr, trusted: True,  # type: ignore
        )

        # Trust a neighbor
        response = authenticated_client.post(
            f"/neighbors/{ip}/trust", follow_redirects=False
        )

        # It should redirect to dashboard
        assert response.status_code == 302
        assert response.headers["Location"] == "/dashboard"


@given(hostname=hostnames, ip=ip_addresses)
def test_untrust_neighbor_redirect_is_valid(
    authenticated_client: FlaskClient, hostname: str, ip: IPv4Address
) -> None:
    """Test that untrusting a neighbor with various IPs redirects properly"""
    with pytest.MonkeyPatch().context() as mp:
        mp.setattr(
            "auto_microk8s_cluster.service.set_neighbour_trusted",
            lambda ip_addr, trusted: True,  # type: ignore
        )

        # Untrust a neighbor
        response = authenticated_client.post(
            f"/neighbors/{ip}/untrust", follow_redirects=False
        )

        # It should redirect to dashboard
        assert response.status_code == 302
        assert response.headers["Location"] == "/dashboard"
