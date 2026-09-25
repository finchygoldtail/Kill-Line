"""Dummy outbound destination: accepts TCP connections on 9000, reads and
DISCARDS whatever arrives (logging only a byte count), then closes."""
import socketserver


class H(socketserver.BaseRequestHandler):
    def handle(self):
        n = 0
        self.request.settimeout(2)
        try:
            while True:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                n += len(chunk)
        except OSError:
            pass
        print(f"dummy-sink: connection from {self.client_address[0]}, {n} bytes discarded", flush=True)


socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer(("0.0.0.0", 9000), H).serve_forever()
