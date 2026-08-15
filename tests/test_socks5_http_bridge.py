import threading
import unittest
from unittest.mock import patch

from g import socks5_http_bridge as bridge_mod


class _FakeBridge:
    starts = 0
    stops = 0

    def __init__(self, upstream):
        self.upstream = upstream
        self._started = False
        self._active_lock = threading.Lock()
        self._active_sockets = set()
        self._handler_threads = set()
        self.port = 20000 + _FakeBridge.starts

    @property
    def playwright_proxy(self):
        return {"server": f"http://127.0.0.1:{self.port}"}

    def start(self):
        type(self).starts += 1
        self._started = True
        return self

    def stop(self):
        if self._started:
            type(self).stops += 1
        self._started = False


class _FakeSocket:
    def __init__(self):
        self.shutdown_calls = 0
        self.close_calls = 0

    def shutdown(self, _how):
        self.shutdown_calls += 1

    def close(self):
        self.close_calls += 1


class _FakeHandler:
    def __init__(self):
        self.join_calls = 0

    def is_alive(self):
        return True

    def join(self, timeout=None):
        self.join_calls += 1


class Socks5BridgeLeaseTests(unittest.TestCase):
    def setUp(self):
        bridge_mod.shutdown_all_bridges()
        _FakeBridge.starts = 0
        _FakeBridge.stops = 0

    def tearDown(self):
        bridge_mod.shutdown_all_bridges()

    def test_same_credentials_share_until_last_release(self):
        spec = "socks5h://user:pass@proxy.test:1080"
        with patch.object(bridge_mod, "socks", object()), patch.object(
            bridge_mod, "Socks5HttpBridge", _FakeBridge
        ):
            first = bridge_mod.acquire_socks5_http_bridge(spec)
            second = bridge_mod.acquire_socks5_http_bridge(spec)
            self.assertEqual(first.playwright_proxy, second.playwright_proxy)
            self.assertEqual(
                bridge_mod.bridge_stats(),
                {
                    "bridges": 1,
                    "references": 2,
                    "active_sockets": 0,
                    "handler_threads": 0,
                },
            )

            first.release()
            self.assertEqual(bridge_mod.bridge_stats()["bridges"], 1)
            second.release()
            self.assertEqual(bridge_mod.bridge_stats()["bridges"], 0)
            self.assertEqual(_FakeBridge.starts, 1)
            self.assertEqual(_FakeBridge.stops, 1)

    def test_1500_dynamic_credentials_return_to_baseline(self):
        with patch.object(bridge_mod, "socks", object()), patch.object(
            bridge_mod, "Socks5HttpBridge", _FakeBridge
        ):
            for index in range(1500):
                lease = bridge_mod.acquire_socks5_http_bridge(
                    f"socks5h://user-{index}:pass@proxy.test:1080"
                )
                self.assertEqual(bridge_mod.bridge_stats()["bridges"], 1)
                lease.release()

            self.assertEqual(
                bridge_mod.bridge_stats(),
                {
                    "bridges": 0,
                    "references": 0,
                    "active_sockets": 0,
                    "handler_threads": 0,
                },
            )
            self.assertEqual(_FakeBridge.starts, 1500)
            self.assertEqual(_FakeBridge.stops, 1500)

    def test_stop_closes_active_tunnel_sockets_and_joins_handler(self):
        bridge = bridge_mod.Socks5HttpBridge.__new__(bridge_mod.Socks5HttpBridge)
        bridge._stop = threading.Event()
        bridge._sock = None
        bridge._thread = None
        bridge._started = True
        bridge._active_lock = threading.Lock()
        first = _FakeSocket()
        second = _FakeSocket()
        handler = _FakeHandler()
        bridge._active_sockets = {first, second}
        bridge._handler_threads = {handler}

        bridge.stop()

        self.assertEqual(first.shutdown_calls, 1)
        self.assertEqual(second.shutdown_calls, 1)
        self.assertEqual(first.close_calls, 1)
        self.assertEqual(second.close_calls, 1)
        self.assertEqual(handler.join_calls, 1)


if __name__ == "__main__":
    unittest.main()
