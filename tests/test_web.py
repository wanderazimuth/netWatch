import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from netwatch import db, web
from netwatch.scanner import Sighting
from netwatch.tracker import apply_scan

TV = "00:11:22:33:44:55"


class WebTest(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        conn = db.connect(self.db_path)
        apply_scan(conn, [Sighting(TV, "192.168.0.20")], 1000, 600)
        conn.close()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(self.db_path))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(self.db_path + suffix)
            except FileNotFoundError:
                pass

    def get(self, path):
        with urllib.request.urlopen(self.base + path) as r:
            return r.status, r.read()

    def post(self, path, body, content_type="application/json"):
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode(), method="POST")
        req.add_header("Content-Type", content_type)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def test_index(self):
        status, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn(b"<title>NetWatch</title>", body)

    def test_devices_and_events(self):
        devices = json.loads(self.get("/api/devices")[1])["devices"]
        self.assertEqual([(d["mac"], d["ip"], d["online"]) for d in devices], [(TV, "192.168.0.20", True)])
        events = json.loads(self.get("/api/events")[1])["events"]
        self.assertEqual([e["kind"] for e in events], ["new"])

    def test_label(self):
        self.assertEqual(self.post(f"/api/devices/{TV}/label", {"label": "Living room TV"}), 200)
        devices = json.loads(self.get("/api/devices")[1])["devices"]
        self.assertEqual(devices[0]["name"], "Living room TV")
        self.assertEqual(self.post(f"/api/devices/{TV}/label", {"label": ""}), 200)
        self.assertEqual(json.loads(self.get("/api/devices")[1])["devices"][0]["name"], TV)

    def test_label_rejects_non_json_and_unknown(self):
        self.assertEqual(self.post(f"/api/devices/{TV}/label", {"label": "x"}, "text/plain"), 415)
        self.assertEqual(self.post("/api/devices/aa:aa:aa:aa:aa:aa/label", {"label": "x"}), 404)

    def test_settings_roundtrip(self):
        s = json.loads(self.get("/api/settings")[1])
        self.assertTrue(s["enabled"])
        self.assertFalse(s["ntfy_configured"])
        self.assertEqual(self.post("/api/settings", {"enabled": False, "quiet_start": "22:00", "quiet_end": "07:00"}), 200)
        s = json.loads(self.get("/api/settings")[1])
        self.assertEqual((s["enabled"], s["quiet_start"]), (False, "22:00"))
        self.assertEqual(self.post("/api/settings", {"quiet_start": "nope"}), 400)

    def test_notify_toggle(self):
        self.assertEqual(self.post(f"/api/devices/{TV}/notify", {"notify": True}), 200)
        self.assertTrue(json.loads(self.get("/api/devices")[1])["devices"][0]["notify"])
        self.assertEqual(self.post(f"/api/devices/{TV}/notify", {"notify": "yes"}), 400)

    def test_test_notification_needs_ntfy(self):
        self.assertEqual(self.post("/api/test-notification", {}), 409)

    def test_favicon(self):
        status, body = self.get("/favicon.svg")
        self.assertEqual(status, 200)
        self.assertTrue(body.startswith(b"<svg"))

    def test_unknown_path(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.get("/nope")
        self.assertEqual(cm.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
