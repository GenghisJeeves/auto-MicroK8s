"""
Type stubs for requests_unixsocket adapters.
"""

import socket
from typing import Any

import urllib3
from requests.adapters import HTTPAdapter, _Uri  # type: ignore
from requests.models import PreparedRequest
from urllib3._base_connection import BaseHTTPConnection
from urllib3._collections import RecentlyUsedContainer
from urllib3.connection import HTTPConnection

class UnixHTTPConnection(HTTPConnection):
    unix_socket_url: str
    sock: socket.socket | None  # Can be `None` if `.connect()` was not called

    def __init__(self, unix_socket_url: str, timeout: int = 60) -> None:
        """Create an HTTP connection to a unix domain socket

        :param unix_socket_url: A URL with a scheme of 'http+unix' and the
        netloc is a percent-encoded path to a unix domain socket. E.g.:
        'http+unix://%2Ftmp%2Fprofilesvc.sock/status/pid'
        """
        ...

    def __del__(self) -> None: ...
    def connect(self) -> None: ...

class UnixHTTPConnectionPool(urllib3.connectionpool.HTTPConnectionPool):
    socket_path: str
    timeout: int

    def __init__(self, socket_path: str, timeout: int = 60) -> None: ...
    def _new_conn(self) -> BaseHTTPConnection: ...

class UnixAdapter(HTTPAdapter):
    timeout: int
    pools: RecentlyUsedContainer[str, UnixHTTPConnectionPool]

    def __init__(
        self, timeout: int = 60, pool_connections: int = 25, *args: Any, **kwargs: Any
    ) -> None: ...
    from typing import Mapping

    def get_connection_with_tls_context(
        self,
        request: PreparedRequest,
        verify: bool | str | None,
        proxies: Mapping[str, str] | None = None,
        cert: str | tuple[str, str] | None = None,
    ) -> UnixHTTPConnectionPool: ...
    from typing import Mapping

    def get_connection(
        self, url: _Uri, proxies: Mapping[str, str] | None = None
    ) -> UnixHTTPConnectionPool: ...
    def request_url(
        self, request: PreparedRequest, proxies: dict[str, str] | None = None
    ) -> str: ...
    def close(self) -> None: ...
