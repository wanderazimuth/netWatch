import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from netwatch.notify import heartbeat


class HeartbeatTest(unittest.TestCase):
    def test_ping(self):
        hits = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.assertTrue(heartbeat(f"http://127.0.0.1:{server.server_port}/abc"))
        self.assertEqual(hits, ["/abc"])
        # Nothing listening: reported, never raised.
        self.assertFalse(heartbeat("http://127.0.0.1:9/abc"))


if __name__ == "__main__":
    unittest.main()
