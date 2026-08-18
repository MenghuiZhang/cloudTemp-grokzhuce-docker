import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import grok
from g.classification_store import ClassificationStore


def jwt(payload):
    enc = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'none'})}.{enc(payload)}.sig"


class _Tos:
    def accept_tos_version(self, **_kwargs):
        return {"ok": False, "error": "skipped in test"}


class _Nsfw:
    def enable_nsfw(self, **_kwargs):
        return {"ok": False}


class BfsRegistrationFlowTests(unittest.TestCase):
    def test_bfs_marked_is_disabled_locally_and_not_counted_clean(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            engine = grok.RegisterEngine(log_fn=lambda *_args: None)
            engine.output_file = str(root / "keys" / "batch.txt")
            engine._classification_store = ClassificationStore(engine.output_file)
            engine.pending_bfs_count = 1
            engine._enrich_pending = 1
            token = {
                "access_token": jwt({"sub": "one", "bfs": 0, "exp": 4_000_000_000}),
                "refresh_token": "refresh",
                "expires_in": 3600,
            }
            with (
                patch.object(grok, "_BASE_DIR", root),
                patch.object(engine, "_exchange_token_after_clean", return_value=token),
            ):
                engine._enrich_after_sso(
                    email="one@example.test",
                    sso=jwt({"session_id": "one"}),
                    sso_rw="",
                    success_id="",
                    impersonate="chrome131",
                    user_agent="",
                    risk_gated=True,
                )
            self.assertEqual(engine.clean_count, 0)
            self.assertEqual(engine.marked_count, 1)
            self.assertEqual(engine.pending_bfs_count, 0)
            cpa = json.loads((root / "converted_auth" / "cpa" / "xai-one@example.test.json").read_text())
            self.assertTrue(cpa["disabled"])
            self.assertEqual(cpa["bfs_status"], "flagged")

    def test_risk_disabled_enrichment_never_calls_oauth(self):
        engine = grok.RegisterEngine(log_fn=lambda *_args: None)
        exchange = Mock()
        engine._enrich_pending = 1
        with (
            patch.object(engine, "_exchange_token_after_clean", exchange),
            patch.object(grok, "UserAgreementService", _Tos),
            patch.object(grok, "NsfwSettingsService", _Nsfw),
        ):
            engine._enrich_after_sso(
                email="unchecked@example.test",
                sso=jwt({"session_id": "unchecked"}),
                sso_rw="",
                success_id="",
                impersonate="chrome131",
                user_agent="",
                skip_token=True,
                risk_gated=False,
            )
        exchange.assert_not_called()


if __name__ == "__main__":
    unittest.main()
