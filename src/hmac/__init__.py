"""
LINE HMAC signing module.

Uses the LTSM WASM module (via Node.js) to compute X-Hmac headers
for LINE Chrome extension API requests.

Two modes:
  1. Subprocess: spawns node per request (simple, slower)
  2. Server: starts a persistent Node.js signer process (fast, recommended)
"""

import os
import json
import subprocess
import urllib.request
import time
import atexit
from pathlib import Path

SIGNER_JS = Path(__file__).parent / "signer.js"
SIGNER_PORT = 18944


class HmacSigner:
    """Compute LINE X-Hmac headers using the WASM module."""

    def __init__(self, mode: str = "server"):
        """
        Args:
            mode: "server" (persistent Node.js process) or "subprocess" (per-request)
        """
        self.mode = mode
        self._server_process = None

        if mode == "server":
            self._start_server()

    def _start_server(self):
        """Start the Node.js HMAC signer server."""
        self._server_process = subprocess.Popen(
            ["node", str(SIGNER_JS), "serve", str(SIGNER_PORT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        atexit.register(self._stop_server)

        # Wait for server to be ready
        for _ in range(50):  # 5 seconds max
            time.sleep(0.1)
            try:
                req = urllib.request.Request(
                    f"http://127.0.0.1:{SIGNER_PORT}/sign",
                    data=json.dumps({
                        "accessToken": "test",
                        "path": "/test",
                        "body": ""
                    }).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=2)
                return  # Server is ready
            except Exception:
                continue

        raise RuntimeError("Failed to start HMAC signer server")

    def _stop_server(self):
        if self._server_process:
            self._server_process.terminate()
            self._server_process.wait(timeout=5)
            self._server_process = None

    def sign(self, access_token: str, path: str, body: str = "") -> str:
        """
        Compute the X-Hmac header value.

        Args:
            access_token: LINE access token (JWT)
            path: Request path (e.g. /api/talk/thrift/Talk/TalkService/sendMessage)
            body: Request body (JSON string or empty)

        Returns:
            Base64-encoded HMAC signature for the X-Hmac header
        """
        if self.mode == "server":
            return self._sign_server(access_token, path, body)
        else:
            return self._sign_subprocess(access_token, path, body)

    def _sign_server(self, access_token: str, path: str, body: str) -> str:
        payload = json.dumps({
            "accessToken": access_token,
            "path": path,
            "body": body,
        }).encode()

        req = urllib.request.Request(
            f"http://127.0.0.1:{SIGNER_PORT}/sign",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=5)
        result = json.loads(resp.read())
        return result["hmac"]

    def _sign_subprocess(self, access_token: str, path: str, body: str) -> str:
        result = subprocess.run(
            ["node", str(SIGNER_JS), "sign", access_token, path, body],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0:
            raise RuntimeError(f"HMAC signer failed: {result.stderr}")
        return result.stdout.strip()

    def __del__(self):
        self._stop_server()
