import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from types import SimpleNamespace

from netwatch import db, web
from netwatch.scanner import Sighting
from netwatch.tracker import apply_scan

TV = "00:11:22:33:44:55"
OTHER = "00:11:22:33:44:66"


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

    def test_down_after(self):
        device = lambda: json.loads(self.get("/api/devices")[1])["devices"][0]
        self.assertEqual((device()["down_after"], device()["down"]), (None, False))
        self.assertEqual(self.post(f"/api/devices/{TV}/down_after", {"minutes": 15}), 200)
        self.assertEqual(device()["down_after"], 15)
        for bad in (1, 99999, "15", True):
            self.assertEqual(self.post(f"/api/devices/{TV}/down_after", {"minutes": bad}), 400, bad)
        self.assertEqual(self.post(f"/api/devices/{TV}/down_after", {"minutes": None}), 200)
        self.assertIsNone(device()["down_after"])

    def test_device_detail(self):
        status, body = self.get(f"/api/devices/{TV}?since=0")
        data = json.loads(body)
        self.assertEqual(data["device"]["mac"], TV)
        self.assertEqual([e["kind"] for e in data["events"]], ["new"])
        h = data["history"]
        # since=0 is clamped to the last 31 days, which starts after this test device was first seen.
        self.assertEqual(h["end"] - h["start"], web.MAX_HISTORY)
        self.assertEqual(h["spans"], [[h["start"], h["end"]]])
        self.assertEqual((data["ports_scanned"], data["ports"]), (None, []))
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.get("/api/devices/aa:aa:aa:aa:aa:aa")
        self.assertEqual(cm.exception.code, 404)

    def test_device_ports(self):
        conn = db.connect(self.db_path)
        conn.execute("INSERT INTO ports VALUES (?, 22, 'tcp', 'ssh', 2000, 3000), (?, 23, 'tcp', 'telnet', 2000, 2000)", (TV, TV))
        conn.execute("UPDATE devices SET ports_scanned = 3000")
        conn.commit()
        conn.close()
        data = json.loads(self.get(f"/api/devices/{TV}")[1])
        self.assertEqual(data["ports_scanned"], 3000)
        self.assertEqual([(p["port"], p["service"], p["open"]) for p in data["ports"]], [(22, "ssh", True), (23, "telnet", False)])

    def test_dns_needs_pihole(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.get(f"/api/devices/{TV}/dns")
        self.assertEqual(cm.exception.code, 409)

    def test_pause_needs_pihole(self):
        self.assertEqual(self.post(f"/api/devices/{TV}/pause", {"until": None}), 409)
        self.assertEqual(self.post(f"/api/devices/{TV}/resume", {}), 409)
        self.assertFalse(json.loads(self.get("/api/settings")[1])["pihole_configured"])
        self.assertFalse(json.loads(self.get("/api/devices")[1])["devices"][0]["paused"])

    def test_only_pausable_devices_can_be_paused(self):
        # A Pi-hole nobody listens on: a listed device gets past the check and then fails to connect.
        pihole = SimpleNamespace(url="http://127.0.0.1:9", password="", sync_trigger="", pausable=[TV])
        server = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(self.db_path, pihole=pihole))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base, self.base = self.base, f"http://127.0.0.1:{server.server_port}"
        try:
            conn = db.connect(self.db_path)
            apply_scan(conn, [Sighting(TV, "192.168.0.20"), Sighting(OTHER, "192.168.0.30")], 1060, 600)
            conn.close()
            devices = {d["mac"]: d["pausable"] for d in json.loads(self.get("/api/devices")[1])["devices"]}
            self.assertEqual(devices, {TV: True, OTHER: False})
            self.assertEqual(self.post(f"/api/devices/{OTHER}/pause", {"until": None}), 403)
            self.assertEqual(self.post(f"/api/devices/{TV}/pause", {"until": None}), 502)
            self.assertEqual(self.post(f"/api/devices/{OTHER}/resume", {}), 200)  # resume is never refused
        finally:
            self.base = base

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


class HistoryTest(unittest.TestCase):
    def setUp(self):
        self.conn = db.connect(":memory:")

    def spans(self, start, end):
        return web.online_spans(self.conn, TV, start, end, offline_after=600)

    def test_spans_from_events(self):
        apply_scan(self.conn, [Sighting(TV, "192.168.0.20")], 1000, 600)  # new
        apply_scan(self.conn, [], 2000, 600)  # offline event at 2000; last seen 1000
        apply_scan(self.conn, [Sighting(TV, "192.168.0.20")], 5000, 600)  # back online
        h = self.spans(0, 6000)
        self.assertEqual(h["known_from"], 1000)
        # Offline detected at 2000 but last seen 600 s before it.
        self.assertEqual(h["spans"], [[1000, 1400], [5000, 6000]])
        self.assertAlmostEqual(h["uptime"], 1400 / 5000)

    def test_window_starts_mid_session(self):
        apply_scan(self.conn, [Sighting(TV, "192.168.0.20")], 1000, 600)
        self.assertEqual(self.spans(3000, 4000)["spans"], [[3000, 4000]])
        apply_scan(self.conn, [], 1700, 600)  # offline
        self.assertEqual(self.spans(3000, 4000)["spans"], [])


class DnsSummaryTest(unittest.TestCase):
    def test_tally(self):
        q = lambda d, status="FORWARDED", t=100: {"domain": d, "status": status, "time": t}
        result = {"queries": [q("a.com"), q("ads.net", "GRAVITY"), q("a.com"), q("ads.net", "GRAVITY", 50)],
                  "recordsFiltered": 4, "earliest_timestamp": 10}
        s = web.dns_summary(result)
        self.assertEqual((s["total"], s["blocked"], s["domains"], s["since"], s["complete"]), (4, 2, 2, 10, True))
        self.assertEqual([(t["domain"], t["count"], t["blocked"]) for t in s["top"]], [("a.com", 2, 0), ("ads.net", 2, 2)])

    def test_truncated_tally_starts_at_oldest_query(self):
        result = {"queries": [{"domain": "a.com", "time": 900.5}, {"domain": "a.com", "time": 800.2}],
                  "recordsFiltered": 50, "earliest_timestamp": 10}
        s = web.dns_summary(result)
        self.assertEqual((s["since"], s["complete"]), (800, False))


if __name__ == "__main__":
    unittest.main()
