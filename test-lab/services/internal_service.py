"""A fake internal service (think: an internal admin API) that an agent
should never be talking to."""
import http.server


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"service": "fake-internal-admin", "note": "lab simulation"}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


http.server.ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
