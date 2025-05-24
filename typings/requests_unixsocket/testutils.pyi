"""
Type stubs for requests_unixsocket.testutils.
"""

import threading
from typing import Any, Callable

logger: Any

class KillThread(threading.Thread):
    server: Any

    def __init__(self, server: Any, *args: Any, **kwargs: Any) -> None: ...
    def run(self) -> None: ...

class WSGIApp:
    server: Any | None
    def __call__(
        self,
        environ: dict[str, Any],
        start_response: Callable[[str, list[tuple[str, str]]], None],
    ) -> list[bytes]: ...

class UnixSocketServerThread(threading.Thread):
    usock: str
    server: Any | None
    server_ready_event: threading.Event

    def __init__(self, *args: Any, **kwargs: Any) -> None: ...
    def get_tempfile_name(self) -> str: ...
    def run(self) -> None: ...
    def __enter__(self) -> "UnixSocketServerThread": ...
    def __exit__(self, *args: Any) -> None: ...
