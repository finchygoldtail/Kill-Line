"""Fake cloud metadata service for the KillLine lab. Serves obviously fake,
static values. There are no real credentials anywhere in this lab."""
import http.server

FAKE = {
    "/latest/meta-data/instance-id": "i-00000000killline",
    "/latest/meta-data/iam/security-credentials/": "fake-role",
    "/latest/meta-data/iam/security-credentials/fake-role":
        '{"AccessKeyId": "FAKE-NOT-A-KEY", "SecretAccessKey": "FAKE-NOT-A-SECRET"}',
}


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = FAKE.get(self.path, "not found").encode()
        self.send_response(200 if self.path in FAKE else 404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


http.server.ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
