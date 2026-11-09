import json
import os
import tempfile
import unittest
from unittest import mock

from netwatch import db, settings, speed

ROKU = "00:11:22:33:44:01"
DOORBELL = "00:11:22:33:44:02"
STRANGER = "00:11:22:33:44:03"  # not in the database yet
NOON = 1792000800  # a top-of-the-hour unix time in any whole-hour time zone

OOKLA = json.dumps({
    "type": "result", "ping": {"jitter": 4.32, "latency": 31.07},
    "download": {"bandwidth": 23_500_000}, "upload": {"bandwidth": 2_250_000}, "packetLoss": 0,
    "server": {"name": "Starlink", "location": "Salt Lake City, UT"},
    "result": {"url": "https://www.speedtest.net/result/c/abc"},
})
PING_OK = """PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.

--- 1.1.1.1 ping statistics ---
20 packets transmitted, 19 received, 5% packet loss, time 3805ms
rtt min/avg/max/mdev = 21.120/38.554/91.031/14.211 ms
"""
PING_DOWN = """--- 1.1.1.1 ping statistics ---
20 packets transmitted, 0 received, 100% packet loss, time 3999ms
"""


class ParseTest(unittest.TestCase):
    def test_ookla(self):
        r = speed.parse_ookla(OOKLA)
        self.assertEqual((r.kind, r.down, r.up, r.ping, r.jitter, r.loss), ("full", 188.0, 18.0, 31.1, 4.3, 0))
        self.assertEqual((r.server, r.url), ("Starlink, Salt Lake City, UT", "https://www.speedtest.net/result/c/abc"))

    def test_ping(self):
        r = speed.parse_ping(PING_OK)
        self.assertEqual((r.kind, r.ping, r.jitter, r.loss), ("ping", 38.6, 14.2, 5.0))
        r = speed.parse_ping(PING_DOWN)
        self.assertEqual((r.ping, r.loss), (None, 100.0))
        with self.assertRaises(ValueError):
            speed.parse_ping("ping: connect: Network is unreachable")

    def test_errors(self):
        import subprocess

        e = subprocess.CalledProcessError(2, "speedtest", stderr='{"type":"log","level":"error","message":"Cannot open socket"}\n')
        self.assertEqual(speed._error(e), "Cannot open socket")
        self.assertEqual(speed._error(FileNotFoundError(2, "No such file", "speedtest")), "speedtest isn't installed")


class RunTest(unittest.TestCase):
    def setUp(self):
        self.conn = db.connect(":memory:")
        for mac, label, kind in ((ROKU, "Roku TV", "tv"), (DOORBELL, "Doorbell", "camera")):
            self.conn.execute("INSERT INTO devices (mac, label, kind, first_seen, last_seen) VALUES (?, ?, ?, 0, 0)",
                              (mac, label, kind))
        self.full = mock.patch.object(speed, "run_full", side_effect=lambda: speed.Result("full", down=190, up=20, ping=30))
        self.ping = mock.patch.object(speed, "run_ping", side_effect=lambda busy: speed.Result("ping", ping=60, busy=busy))
        self.run_full, self.run_ping = self.full.start(), self.ping.start()
        self.addCleanup(mock.patch.stopall)

    def kinds(self):
        return [r["kind"] for r in self.conn.execute("SELECT kind FROM speedtests ORDER BY id")]

    def test_busy_devices(self):
        traffic = {ROKU: (2936, 39), DOORBELL: (14, 603), STRANGER: (1200, 0)}
        # The doorbell uploads all day and doesn't count; a device not reviewed yet does.
        self.assertEqual(speed.busy_devices(self.conn, traffic, 1000), ["Roku TV", STRANGER])
        self.assertEqual(speed.busy_devices(self.conn, traffic, 5000), [])

    def test_quiet_hour_tests_once(self):
        quiet = lambda: {DOORBELL: (10, 900)}
        self.assertEqual(speed.run(self.conn, NOON + 60, quiet, 1).kind, "full")
        self.assertIsNone(speed.run(self.conn, NOON + 660, quiet, 1))
        self.assertEqual(speed.run(self.conn, NOON + 3600, quiet, 1).kind, "full")  # next hour
        self.assertEqual(self.kinds(), ["full", "full"])

    def test_busy_pings_once_then_tests_when_quiet(self):
        streaming = lambda: {ROKU: (2900, 40)}
        r = speed.run(self.conn, NOON + 60, streaming, 1)
        self.assertEqual((r.kind, r.busy), ("ping", "Roku TV"))
        self.assertIsNone(speed.run(self.conn, NOON + 660, streaming, 1))  # still busy: no second ping check
        self.assertEqual(speed.run(self.conn, NOON + 1260, lambda: {}, 1).kind, "full")
        self.assertEqual(self.kinds(), ["ping", "full"])
        self.run_full.assert_called_once()

    def test_deco_unreachable_counts_as_busy(self):
        r = speed.run(self.conn, NOON, lambda: None, 1)
        self.assertEqual((r.kind, r.busy), ("ping", "couldn't check the Deco"))

    def test_no_deco_always_tests(self):
        self.assertEqual(speed.run(self.conn, NOON, None, 1).kind, "full")

    def test_forced_ignores_busy_and_the_hours_test(self):
        speed.run(self.conn, NOON, None, 1)
        r = speed.run(self.conn, NOON + 60, lambda: {ROKU: (9000, 0)}, 1, force=True)
        self.assertEqual(r.kind, "full")
        self.assertEqual(self.kinds(), ["full", "full"])

    def test_results(self):
        speed.run(self.conn, NOON, None, 1)
        rows = speed.results(self.conn, NOON - 1)
        self.assertEqual((rows[0]["down"], rows[0]["up"], rows[0]["ts"]), (190, 20, NOON))
        self.assertEqual(speed.results(self.conn, NOON + 1), [])


class DecoBackoffTest(unittest.TestCase):
    def setUp(self):
        self.conn = db.connect(":memory:")
        fd, self.pw = tempfile.mkstemp()
        os.close(fd)
        self.addCleanup(os.remove, self.pw)

    def test_backs_off_after_a_failure(self):
        fail = mock.Mock(side_effect=OSError("login failed"))
        with self.assertLogs("netwatch.speed", "WARNING"):
            self.assertIsNone(speed.deco_traffic(self.conn, fail, self.pw, NOON))
        # 20 minutes after one failure: not yet, so no extra failed login.
        self.assertIsNone(speed.deco_traffic(self.conn, fail, self.pw, NOON + 600))
        self.assertEqual(fail.call_count, 1)
        ok = mock.Mock(return_value={ROKU: (1, 1)})
        self.assertEqual(speed.deco_traffic(self.conn, ok, self.pw, NOON + 1200), {ROKU: (1, 1)})

    def test_new_password_retries_straight_away(self):
        with self.assertLogs("netwatch.speed", "WARNING"):
            speed.deco_traffic(self.conn, mock.Mock(side_effect=OSError("bad password")), self.pw, NOON)
        os.utime(self.pw, (NOON + 5, NOON + 5))
        self.assertEqual(speed.deco_traffic(self.conn, mock.Mock(return_value={}), self.pw, NOON + 60), {})


class RequestTest(unittest.TestCase):
    def test_take_request(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(speed.take_request(d))
            open(os.path.join(d, speed.REQUEST_FILE), "w").close()
            self.assertTrue(speed.take_request(d))
            self.assertFalse(speed.take_request(d))


class SettingsTest(unittest.TestCase):
    def test_speed_settings(self):
        self.assertEqual(settings.validate({"speed_busy_mbps": 2.5, "speed_plan_mbps": 200}),
                         {"speed_busy_mbps": 2.5, "speed_plan_mbps": 200})
        for bad in ({"speed_busy_mbps": 0}, {"speed_busy_mbps": "1"}, {"speed_plan_mbps": -1}, {"speed_tests": 1}):
            with self.assertRaises(ValueError, msg=bad):
                settings.validate(bad)


if __name__ == "__main__":
    unittest.main()
