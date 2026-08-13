import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import grok
from g.domain_pool import DomainPool
from g.proxy_pool import ProxyPool


class FakeEmailService:
    provider_name = "cloudflare_temp"
    structured_config = {
        "providers": {"cloudflare_temp": {"domains": ["mail.example"]}}
    }

    def __init__(self, *args, **kwargs):
        self.created = 0

    def set_register_proxy(self, _spec):
        return None

    def create_email_for_domain(self, domain):
        self.created += 1
        address = f"user{self.created}@{domain}"
        return f"jwt-{self.created}", address

    def get_email_metadata(self, email):
        return {"email_provider": "cloudflare_temp", "email_domain": email.rsplit("@", 1)[-1]}

    def fetch_verification_code(self, *_args, **_kwargs):
        return "ABC-123"

    def delete_email(self, _email):
        return True


class FakeTurnstileService:
    yescaptcha_key = "configured"
    solver_url = "fake"

    def create_task(self, *_args, **_kwargs):
        return "task"

    def get_response(self, *_args, **_kwargs):
        return "token"


class BotRevalidationFlowTests(unittest.TestCase):
    def make_engine(self, root: Path, proxy_count: int):
        proxy_pool = ProxyPool(root / "proxy_pool.json")
        proxy_pool.import_text("\n".join(f"p{i}.example:80{i}" for i in range(proxy_count)))
        domain_pool = DomainPool(root / "domain_pool.json")
        domain_pool.sync_configured(["mail.example"])
        engine = grok.RegisterEngine(log_fn=lambda *_args: None)
        engine.proxy_pool = proxy_pool
        engine.domain_pool = domain_pool
        engine.workers = 1
        engine.target_count = 1
        engine.risk_check_enabled = True
        engine.output_file = None
        return engine, proxy_pool, domain_pool

    @staticmethod
    def marked_probe(engine):
        def probe(**_kwargs):
            engine.marked_count += 1
            return False

        return probe

    def run_worker(self, engine, root):
        with (
            patch.object(grok, "EmailService", FakeEmailService),
            patch.object(grok, "TurnstileService", FakeTurnstileService),
            patch.object(grok, "same_session_register", return_value={"ok": True, "sso": "sso", "sso_rw": "sso", "steps": []}),
            patch.object(grok, "_ss_inter_account_delay", return_value=0),
            patch.object(grok, "_BASE_DIR", root),
            patch.object(engine, "_probe_and_mark_clean", side_effect=self.marked_probe(engine)),
            patch.object(engine, "_write_account_json_unlocked"),
        ):
            engine.register_single_thread_same_session()

    def test_two_marked_attempts_disable_both_proxies_and_domain(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine, proxies, domains = self.make_engine(root, 2)
            self.run_worker(engine, root)

            self.assertEqual(engine.attempt_count, 1)
            self.assertEqual(engine.email_create_count, 2)
            self.assertEqual(engine.bot_retry_count, 1)
            self.assertEqual(proxies.summary()["disabled"], 2)
            domain = domains.list_public(status="disabled")["items"][0]
            self.assertEqual(domain["disabled_reason"], "BOT_MARKED_TWICE")
            self.assertEqual(domain["bot_first_failures"], 1)
            self.assertEqual(domain["bot_second_failures"], 1)

    def test_no_alternate_proxy_stops_without_disabling_domain(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine, proxies, domains = self.make_engine(root, 1)
            self.run_worker(engine, root)

            self.assertEqual(engine.resource_exhausted_reason, "PROXY_EXHAUSTED")
            self.assertEqual(proxies.summary()["disabled"], 1)
            domain = domains.list_public()["items"][0]
            self.assertEqual(domain["status"], "enabled")
            self.assertEqual(domain["bot_first_failures"], 1)
            self.assertEqual(domain["bot_second_failures"], 0)


if __name__ == "__main__":
    unittest.main()
