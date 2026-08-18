import threading
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import grok
from g.domain_pool import DomainPool
from g.proxy_pool import ProxyPool


class EmailCreationTargetTests(unittest.TestCase):
    def make_engine(self, target=3):
        engine = grok.RegisterEngine(log_fn=lambda *_args: None)
        engine.target_count = target
        engine.attempt_count = 0
        engine.email_create_count = 0
        engine._email_create_reserved = 0
        return engine

    def test_concurrent_reservations_never_exceed_target(self):
        engine = self.make_engine(target=5)
        barrier = threading.Barrier(20)
        results = []
        lock = threading.Lock()

        def reserve():
            barrier.wait()
            value = engine._reserve_email_creation()
            with lock:
                results.append(value)

        threads = [threading.Thread(target=reserve) for _ in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        accepted = [value for value in results if value]
        self.assertEqual(len(accepted), 5)
        self.assertEqual(engine._email_create_reserved, 5)
        for _ in accepted:
            engine._finish_email_creation(success=True)
        self.assertEqual(engine.email_create_count, 5)
        self.assertEqual(engine._email_create_reserved, 0)
        self.assertEqual(engine._reserve_email_creation(), 0)

    def test_failed_create_does_not_consume_target_slot(self):
        engine = self.make_engine(target=1)
        self.assertEqual(engine._reserve_email_creation(), 1)
        engine._finish_email_creation(success=False)
        self.assertEqual(engine.email_create_count, 0)
        self.assertEqual(engine._reserve_email_creation(), 2)
        engine._finish_email_creation(success=True)
        self.assertEqual(engine.email_create_count, 1)
        self.assertEqual(engine.attempt_count, 2)

    def test_status_progress_and_average_use_created_email_count(self):
        engine = self.make_engine(target=4)
        engine.start_time = 100.0
        engine.end_time = 108.0
        engine.status = "done"
        engine.email_create_count = 2
        engine.success_count = 1
        status = engine.get_status()
        self.assertEqual(status["progress"], 50.0)
        self.assertEqual(status["avg_seconds"], 4.0)

    def test_protocol_path_uses_live_domain_pool_for_email_creation(self):
        created_domains = []

        class EmailService:
            provider_name = "cloudflare_temp"

            def __init__(self, *args, **kwargs):
                pass

            def set_register_proxy(self, _spec):
                pass

            def create_email_for_domain(self, domain):
                created_domains.append(domain)
                return "jwt", f"user@{domain}"

            def get_email_metadata(self, email):
                return {"email_provider": "cloudflare_temp", "email_domain": email.split("@")[-1]}

            def delete_email(self, _email):
                return True

        class TurnstileService:
            yescaptcha_key = "configured"

        class CastleService:
            mode = "skip"

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            engine = self.make_engine(target=1)
            engine.config["action_id"] = "action"
            engine.domain_pool = DomainPool(root / "domains.json")
            engine.domain_pool.sync_configured(["first.example", "second.example"])
            engine.proxy_pool = ProxyPool(root / "proxies.json")
            session = MagicMock()
            session.__enter__.return_value = session
            session.__exit__.return_value = False
            with (
                patch.object(grok, "EmailService", EmailService),
                patch.object(grok, "TurnstileService", TurnstileService),
                patch.object(grok, "CastleService", CastleService),
                patch.object(grok.requests, "Session", return_value=session),
                patch.object(engine, "send_email_code_grpc", return_value=False),
                patch.object(engine, "_sleep", return_value=False),
            ):
                engine.register_single_thread()

            self.assertEqual(created_domains, ["first.example"])
            self.assertEqual(engine.email_create_count, 1)
            self.assertEqual(engine.domain_pool.summary()["busy"], 0)


if __name__ == "__main__":
    unittest.main()
