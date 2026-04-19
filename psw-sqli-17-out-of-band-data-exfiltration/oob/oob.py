"""
Out-of-band interaction recorder with Postgres wire-protocol parsing.

Stands in for Burp Collaborator inside the compose network. Two
listeners:

- TCP :5432 - every accepted connection is logged. A raw libpq client
  (which is what `dblink_connect` uses under the hood) opens with an
  SSLRequest message; we reply with 'N' (no SSL) so the client proceeds
  to send its real startup message, which contains every connection-
  string parameter as a null-terminated key/value pair. We parse those
  parameters and expose them on the HTTP log so any attacker-controlled
  value (e.g. an administrator password stitched into `user=...`) is
  readable verbatim. Up to 1 KiB of raw bytes is kept too for
  anything non-libpq.

- HTTP :8080/log - returns the in-memory log as JSON so the web
  container can render it. /reset clears the log between attempts.
"""

import asyncio
import datetime
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


MAX_LOG_ENTRIES = 200
MAX_BYTES_READ = 1024
TCP_READ_TIMEOUT = 2.0

# libpq SSLRequest: length=8 (big-endian int32), code=80877103.
SSL_REQUEST_CODE = 80877103

# Postgres v3.0 startup protocol version.
PG_PROTOCOL_V3 = 0x00030000

_log: list[dict] = []
_log_lock = threading.Lock()


def _parse_pg_startup(data: bytes) -> dict | None:
    """Parse a Postgres v3.0 StartupMessage into its parameter dict.

    Layout:
        int32 length (including itself)
        int32 protocol (0x00030000 for v3.0)
        sequence of cstring key, cstring value
        terminating \\x00

    Returns None if the payload does not look like a v3.0 startup.
    """
    if len(data) < 8:
        return None
    length = int.from_bytes(data[:4], "big")
    protocol = int.from_bytes(data[4:8], "big")
    if protocol != PG_PROTOCOL_V3:
        return None
    end = min(length, len(data))
    body = data[8:end]
    params: dict[str, str] = {}
    tokens = body.split(b"\x00")
    i = 0
    while i + 1 < len(tokens):
        key = tokens[i]
        if not key:
            break
        value = tokens[i + 1]
        params[key.decode("utf-8", "replace")] = value.decode("utf-8", "replace")
        i += 2
    return params


def _record_connection(peer: str, data: bytes) -> None:
    entry = {
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        "peer": peer,
        "bytes": len(data),
        "preview_hex": data[:64].hex(),
        "pg_params": _parse_pg_startup(data),
    }
    with _log_lock:
        _log.append(entry)
        if len(_log) > MAX_LOG_ENTRIES:
            del _log[:-MAX_LOG_ENTRIES]
    print(
        f"[oob] captured {len(data)}B from {peer} "
        f"(pg_params={entry['pg_params']})",
        flush=True,
    )


async def _read_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    try:
        return await asyncio.wait_for(reader.readexactly(n), TCP_READ_TIMEOUT)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
        return b""


async def _read_some(reader: asyncio.StreamReader, n: int) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(n), TCP_READ_TIMEOUT)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        return b""


async def _handle_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    peer_s = f"{peer[0]}:{peer[1]}" if peer else "unknown"

    head = await _read_exact(reader, 8)
    data: bytes
    if len(head) == 8:
        length = int.from_bytes(head[:4], "big")
        code = int.from_bytes(head[4:], "big")
        if length == 8 and code == SSL_REQUEST_CODE:
            # libpq: decline SSL so the client sends a plaintext startup next.
            try:
                writer.write(b"N")
                await writer.drain()
            except (ConnectionError, OSError):
                pass
            data = await _read_some(reader, MAX_BYTES_READ)
        else:
            rest = await _read_some(reader, MAX_BYTES_READ - 8)
            data = head + rest
    else:
        # Partial or empty read (e.g. plain `nc` with no stdin).
        data = head

    _record_connection(peer_s, data)
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass


async def _tcp_main() -> None:
    server = await asyncio.start_server(_handle_tcp, "0.0.0.0", 5432)
    print("[oob] TCP listener ready on 0.0.0.0:5432", flush=True)
    async with server:
        await server.serve_forever()


class _LogHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path == "/log":
            with _log_lock:
                self._send_json(200, {"entries": list(_log), "count": len(_log)})
        elif self.path == "/healthz":
            self._send_json(200, {"ok": True})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        if self.path == "/reset":
            with _log_lock:
                _log.clear()
            self._send_json(200, {"ok": True})
        else:
            self._send_json(404, {"error": "not found"})

    def log_message(self, *args, **kwargs):
        return


def _run_http() -> None:
    print("[oob] HTTP log endpoint ready on 0.0.0.0:8080/log", flush=True)
    HTTPServer(("0.0.0.0", 8080), _LogHandler).serve_forever()


def main() -> None:
    threading.Thread(target=_run_http, daemon=True).start()
    asyncio.run(_tcp_main())


if __name__ == "__main__":
    main()
