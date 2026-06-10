#!/usr/bin/env python3
"""
Vulnerable test server for CVE-2022-44268

Simulates an image-processing service that runs ImageMagick convert on every
uploaded PNG (e.g. to resize or re-encode before storing). ImageMagick
7.1.0-49 and earlier resolves the "Raw profile type" tEXt chunk injected
into a PNG as a filesystem path and embeds the file contents (hex-encoded)
into the converted output image.

The converted output is what is stored and served back, so an attacker can
upload a crafted PNG, download the converted result, and read arbitrary files
from the server filesystem.

Bundled ImageMagick 7.1.0-49 binaries (bin/imagemagick/):
  macOS          : convert-darwin / identify-darwin  (fat binary: arm64 + x86_64)
  Linux x86_64   : convert-linux-x86_64
  Linux x86      : convert-linux-x86
  Linux aarch64  : convert-linux-aarch64
  Windows x86_64 : convert-windows-x86_64.exe
  Windows x86    : convert-windows-x86.exe

The correct binary is selected automatically based on the host platform.

Usage:
    python3 server.py [port]        default port: 9090

Upload scanner configuration:
    Upload endpoint : POST http://127.0.0.1:<port>/upload  (field: file)
    Download prefix : http://127.0.0.1:<port>/download/
"""

import os
import platform
import subprocess
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer

_BIN_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "bin", "imagemagick")
)


def _select_binary(name):
    """Return the path to the platform-appropriate ImageMagick binary."""
    system = platform.system()
    if system == "Darwin":
        return os.path.join(_BIN_DIR, f"{name}-darwin")
    if system == "Linux":
        machine = platform.machine()
        if machine in ("x86_64", "amd64"):
            suffix = "linux-x86_64"
        elif machine in ("i386", "i486", "i586", "i686"):
            suffix = "linux-x86"
        elif machine in ("aarch64", "arm64"):
            suffix = "linux-aarch64"
        else:
            suffix = f"linux-{machine}"
        return os.path.join(_BIN_DIR, f"{name}-{suffix}")
    if system == "Windows":
        machine = platform.machine()
        if machine in ("AMD64", "x86_64"):
            return os.path.join(_BIN_DIR, f"{name}-windows-x86_64.exe")
        return os.path.join(_BIN_DIR, f"{name}-windows-x86.exe")
    # Fallback
    return os.path.join(_BIN_DIR, f"{name}-darwin")


CONVERT = _select_binary("convert")
IDENTIFY = _select_binary("identify")

# In-memory store: filename -> raw bytes of the *converted* output file
_store = {}

HTML_FORM = b"""\
<!DOCTYPE html>
<html>
<head><title>Image Converter</title></head>
<body>
<h2>Image Converter</h2>
<p>Uploads are processed with ImageMagick convert before storage.</p>
<form method="POST" action="/upload" enctype="multipart/form-data">
  <input type="file" name="file"><br><br>
  <input type="submit" value="Upload &amp; Convert">
</form>
</body>
</html>
"""


def _parse_multipart(rfile, content_type, content_length):
    """Return (filename, data) from a multipart/form-data body."""
    import email
    boundary = None
    for part in content_type.split(";"):
        part = part.strip()
        if part.startswith("boundary="):
            boundary = part[len("boundary="):].strip('"')
            break
    if not boundary:
        return None, None

    raw = rfile.read(content_length)
    msg = email.message_from_bytes(
        b"Content-Type: " + content_type.encode() + b"\r\n\r\n" + raw
    )
    for part in msg.walk():
        cd = part.get("Content-Disposition", "")
        if 'name="file"' in cd or "name=file" in cd:
            filename = "upload"
            for token in cd.split(";"):
                token = token.strip()
                if token.startswith("filename="):
                    filename = token[len("filename="):].strip('"')
            return filename, part.get_payload(decode=True)
    return None, None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[{self.address_string()}] {fmt % args}")

    def do_GET(self):
        if self.path in ("/", "/index.html", "/upload", "/upload/"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(HTML_FORM)

        elif self.path.startswith("/download/"):
            filename = self.path[len("/download/"):]
            data = _store.get(filename)
            if data is None:
                self._respond(404, b"File not found")
            else:
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path not in ("/upload", "/upload/"):
            self.send_response(404)
            self.end_headers()
            return

        content_type = self.headers.get("Content-Type", "")
        content_length = int(self.headers.get("Content-Length", 0))

        if "multipart/form-data" not in content_type:
            self._respond(400, b"Expected multipart/form-data")
            return

        filename, data = _parse_multipart(self.rfile, content_type, content_length)

        if not data:
            self._respond(400, b"No file received")
            return

        _, suffix = os.path.splitext(filename)
        suffix = suffix or ".png"

        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp_in:
            tmp_in.write(data)
            tmp_in_path = tmp_in.name

        tmp_out_path = tmp_in_path + "_converted.png"

        try:
            result = subprocess.run(
                [CONVERT, tmp_in_path, tmp_out_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            convert_stderr = result.stderr.strip()

            if os.path.exists(tmp_out_path):
                with open(tmp_out_path, "rb") as f:
                    converted_data = f.read()
                # Store the converted output — this is what contains the
                # exfiltrated file data when the input is a CVE-2022-44268 payload
                _store[filename] = converted_data
                convert_status = f"convert exited {result.returncode}"
                if convert_stderr:
                    convert_status += f": {convert_stderr}"
            else:
                converted_data = None
                convert_status = f"convert produced no output (exit {result.returncode})"
                if convert_stderr:
                    convert_status += f": {convert_stderr}"

        except subprocess.TimeoutExpired:
            converted_data = None
            convert_status = "[convert timed out]"
        except FileNotFoundError:
            converted_data = None
            convert_status = f"[convert not found at {CONVERT}]"
        except Exception as exc:
            converted_data = None
            convert_status = f"[Error running convert: {exc}]"
        finally:
            for p in (tmp_in_path, tmp_out_path):
                try:
                    os.unlink(p)
                except OSError:
                    pass

        if converted_data:
            body = (
                "<!DOCTYPE html><html><body>"
                f"<h2>Converted: {filename}</h2>"
                f"<p>Status: {convert_status}</p>"
                f"<p>Output size: {len(converted_data)} bytes</p>"
                f'<p><a href="/download/{filename}">Download converted file</a></p>'
                '<p><a href="/">Upload another</a></p>'
                "</body></html>"
            ).encode()
        else:
            body = (
                "<!DOCTYPE html><html><body>"
                f"<h2>Conversion failed: {filename}</h2>"
                f"<p>Status: {convert_status}</p>"
                '<p><a href="/">Upload another</a></p>'
                "</body></html>"
            ).encode()

        self._respond(200, body, content_type="text/html")

    def _respond(self, code, body, content_type="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9090
    try:
        result = subprocess.run([CONVERT, "--version"], capture_output=True, text=True)
        version_line = result.stdout.splitlines()[0] if result.stdout else "(unknown)"
    except FileNotFoundError:
        version_line = f"NOT FOUND at {CONVERT}"
    print(f"[*] platform        : {platform.system()} {platform.machine()}")
    print(f"[*] convert path    : {CONVERT}")
    print(f"[*] ImageMagick     : {version_line}")
    print(f"[!] CVE-2022-44268 affects ImageMagick <= 7.1.0-49 — test environment only")
    print(f"[*] Listening on http://0.0.0.0:{port}")
    print(f"[*] Upload endpoint : POST http://127.0.0.1:{port}/upload  (field: file)")
    print(f"[*] Download prefix : http://127.0.0.1:{port}/download/")
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
