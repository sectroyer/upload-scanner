#!/usr/bin/env python3
"""
Vulnerable test server for CVE-2021-22204

Simulates an image-metadata service that runs ExifTool on every uploaded
file (e.g. to strip EXIF before storing). Uses the bundled ExifTool 10.96
which is vulnerable to arbitrary command execution via crafted DjVu ANTa
annotations embedded in any file extension ExifTool accepts.

Usage:
    python3 server.py [port]       default port: 9090

Upload scanner configuration:
    Upload endpoint : POST http://127.0.0.1:<port>/upload  (field: file)
    Download prefix : http://127.0.0.1:<port>/download/
"""

import os
import subprocess
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer

EXIFTOOL = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "bin", "exiftool.pl")
)

# In-memory store: filename -> raw bytes of the uploaded file
_store = {}

HTML_FORM = b"""\
<!DOCTYPE html>
<html>
<head><title>Image Metadata Extractor</title></head>
<body>
<h2>Image Metadata Extractor</h2>
<p>Uploads are processed with ExifTool to display metadata.</p>
<form method="POST" action="/upload" enctype="multipart/form-data">
  <input type="file" name="file"><br><br>
  <input type="submit" value="Upload &amp; Extract">
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

        # Store the raw upload so /download/<filename> can serve it back
        _store[filename] = data

        _, suffix = os.path.splitext(filename)
        suffix = suffix or ".jpg"

        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                ["perl", EXIFTOOL, tmp_path],
                capture_output=True,
                text=True,
                timeout=60,
            )
            exif_output = (result.stdout + result.stderr).strip() or "(no output)"
        except subprocess.TimeoutExpired:
            exif_output = "[ExifTool timed out]"
        except Exception as exc:
            exif_output = f"[Error running ExifTool: {exc}]"
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

        body = (
            "<!DOCTYPE html><html><body>"
            f"<h2>Metadata for: {filename}</h2>"
            f"<pre>{exif_output}</pre>"
            f'<p><a href="/download/{filename}">Download file</a></p>'
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
    print(f"[*] ExifTool path    : {EXIFTOOL}")
    print(f"[*] ExifTool version : 10.96 (vulnerable, CVE-2021-22204 affects < 12.24)")
    print(f"[!] This server is intentionally vulnerable — test environment only")
    print(f"[*] Listening on http://0.0.0.0:{port}")
    print(f"[*] Upload endpoint  : POST http://127.0.0.1:{port}/upload  (field: file)")
    print(f"[*] Download prefix  : http://127.0.0.1:{port}/download/")
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
