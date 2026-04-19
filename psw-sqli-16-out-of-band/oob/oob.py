"""
Out-of-band interaction recorder.

Stands in for Burp Collaborator inside the compose network. Two
listeners:

- TCP :5432 - accepts any inbound TCP connection, reads up to 1 KiB,
  then closes. Every accepted connection is appended to an in-memory
  log (timestamp, peer address, byte count, hex preview). Only a
  payload that makes the `db` container reach out here triggers this,
  so it is the authoritative proof-of-exploit signal.

- HTTP :8080/log - returns the in-memory log as JSON so the web
  container can decide whether to reveal the flag. /reset clears the
  log (useful between attempts).
"""

import asyncio
import datetime
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


MAX_LOG_ENTRIES = 200
MAX_BYTES_READ = 1024
TCP_READ_TIMEOUT = 2.0

_log: list[dict] = []
_log_lock = threading.Lock()


def _record_connection(peer: str, data: bytes) -> None:
    entry = {
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        "peer": peer,
        "bytes": len(data),
        "preview_hex": data[:64].hex(),
    }
    with _log_lock:
        _log.append(entry)
        if len(_log) > MAX_LOG_ENTRIES:
            del _log[:-MAX_LOG_ENTRIES]
    print(f"[oob] captured connection from {peer}, {len(data)} bytes", flush=True)


async def _handle_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    peer_s = f"{peer[0]}:{peer[1]}" if peer else "unknown"
    try:
        data = await asyncio.wait_for(reader.read(MAX_BYTES_READ), TCP_READ_TIMEOUT)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        data = b""
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

    def log_message(self, *args, **kwargs):  # silence stock logging
        return


def _run_http() -> None:
    print("[oob] HTTP log endpoint ready on 0.0.0.0:8080/log", flush=True)
    HTTPServer(("0.0.0.0", 8080), _LogHandler).serve_forever()


def main() -> None:
    threading.Thread(target=_run_http, daemon=True).start()
    asyncio.run(_tcp_main())


if __name__ == "__main__":
    main()
