import base64
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from convert_sso_json import (
    GROK_BUILD_BASE_URL,
    PROXY_ENV_KEYS,
    build_cpa_record,
    build_sub2api_account,
    cpa_path_for_record,
    configure_network,
    discover_records,
    is_access_denied_failure,
    load_cpa_token,
    move_to_failed_dir,
    SSORecord,
)


def fake_jwt(payload):
    encode = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
    return ".".join(
        [
            encode(b'{"alg":"none"}'),
            encode(json.dumps(payload).encode()),
            "signature",
        ]
    )


class ConvertSSOJsonTests(unittest.TestCase):
    def test_identifies_only_invalid_grant_access_denied(self):
        self.assertTrue(
            is_access_denied_failure("invalid_grant: Access denied")
        )
        self.assertTrue(
            is_access_denied_failure("OAuth failed: INVALID_GRANT / access_denied")
        )
        self.assertFalse(is_access_denied_failure("invalid_grant: expired code"))
        self.assertFalse(is_access_denied_failure("network access denied"))

    def test_moves_access_denied_account_without_overwriting(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "account.json"
            failed = root / "失败"
            failed.mkdir()
            (failed / "account.json").write_text("old", encoding="utf-8")
            source.write_text("new", encoding="utf-8")

            target = move_to_failed_dir(source, failed)

            self.assertEqual(target.name, "account-2.json")
            self.assertFalse(source.exists())
            self.assertEqual(target.read_text(encoding="utf-8"), "new")

    def test_recursive_discovery_excludes_failed_dir(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            failed = root / "失败"
            failed.mkdir()
            token = fake_jwt({"session_id": "one"})
            (root / "active.json").write_text(
                json.dumps({"sso": token}), encoding="utf-8"
            )
            (failed / "denied.json").write_text(
                json.dumps({"sso": fake_jwt({"session_id": "two"})}),
                encoding="utf-8",
            )

            records, errors = discover_records(
                root, recursive=True, excluded_dir=failed
            )

            self.assertEqual([record.source.name for record in records], ["active.json"])
            self.assertEqual(errors, [])

    def test_reuses_existing_cpa_token(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            record = SSORecord(
                source=Path("source.json"),
                email="resume@example.com",
                sso="header.payload.signature",
            )
            path = cpa_path_for_record(output, record)
            path.parent.mkdir(parents=True)
            path.write_text(
                json.dumps(
                    {
                        "type": "xai",
                        "access_token": "access",
                        "refresh_token": "refresh",
                        "expired": "2030-01-01T00:00:00Z",
                    }
                ),
                encoding="utf-8",
            )

            token = load_cpa_token(path)

            self.assertEqual(token["access_token"], "access")
            self.assertEqual(token["refresh_token"], "refresh")

    def test_direct_mode_clears_inherited_proxies(self):
        inherited = {key: "http://127.0.0.1:7890" for key in PROXY_ENV_KEYS}
        with patch.dict("os.environ", inherited, clear=False):
            mode = configure_network()
            self.assertEqual(mode, "直连")
            for key in PROXY_ENV_KEYS:
                self.assertNotIn(key, __import__("os").environ)
            self.assertEqual(__import__("os").environ["NO_PROXY"], "*")

    def test_discovers_and_deduplicates_sso(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            token = fake_jwt({"session_id": "one"})
            for name in ("a.json", "b.json"):
                (folder / name).write_text(
                    json.dumps({"email": f"{name}@example.com", "sso": token}),
                    encoding="utf-8",
                )
            (folder / "bad.json").write_text("not json", encoding="utf-8")

            records, errors = discover_records(folder)

            self.assertEqual(len(records), 1)
            self.assertEqual(len(errors), 2)
            self.assertEqual(records[0].sso, token)

    def test_builds_cpa_xai_record(self):
        access = fake_jwt(
            {
                "sub": "user-1",
                "email": "user@example.com",
                "exp": 2_000_000_000,
            }
        )
        record = build_cpa_record(
            {
                "access_token": access,
                "refresh_token": "refresh",
                "expires_in": 3600,
            }
        )

        self.assertEqual(record["type"], "xai")
        self.assertEqual(record["auth_kind"], "oauth")
        self.assertEqual(record["email"], "user@example.com")
        self.assertEqual(record["base_url"], GROK_BUILD_BASE_URL)
        self.assertEqual(record["headers"]["X-XAI-Token-Auth"], "xai-grok-cli")

    def test_builds_sub2api_grok_account(self):
        access = fake_jwt(
            {
                "sub": "user-2",
                "email": "grok@example.com",
                "principal_type": "User",
                "exp": 2_000_000_000,
            }
        )
        account = build_sub2api_account(
            {"access_token": access, "refresh_token": "refresh"},
            group_ids=[3, 3, 5],
        )

        self.assertEqual(account["platform"], "grok")
        self.assertEqual(account["type"], "oauth")
        self.assertEqual(account["group_ids"], [3, 5])
        self.assertEqual(account["credentials"]["user_id"], "user-2")
        self.assertEqual(account["credentials"]["base_url"], GROK_BUILD_BASE_URL)


if __name__ == "__main__":
    unittest.main()
