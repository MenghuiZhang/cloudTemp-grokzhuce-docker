"""Manual offline browser smoke: python3 tests/account_checks_browser_smoke.py.

Uses an isolated headless Chrome profile, local fake accounts and a fake checker.
No real account requests or changes to the running application.
"""
import json
import sys
import tempfile
import threading
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from g.account_check import now
from g.account_check_api import create_check_blueprint
from g.account_check_jobs import CheckJobs


class Checker:
    def check(self, account, *args, **kwargs):
        return {"state": "review", "reason": "MISSING_THINKING", "checked_at": now(),
                "quality": {"tps": 84, "output_tokens": 128, "has_thinking": False}}


def authenticate(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if request.headers.get("X-Monitor-Token") != "smoke-test-only":
            return jsonify(ok=False, message="unauthorized"), 401
        return fn(*args, **kwargs)
    return wrapped


def main():
    with tempfile.TemporaryDirectory(prefix="account-check-ui-") as temp:
        jobs = CheckJobs(Path(temp), Checker())
        app = Flask(__name__, template_folder=str(ROOT / "templates"), static_folder=str(ROOT / "static"))
        app.register_blueprint(create_check_blueprint(jobs, authenticate))
        server = make_server("127.0.0.1", 0, app)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(channel="chrome", headless=True, args=["--disable-background-networking"])
                page = browser.new_page(viewport={"width": 1440, "height": 1100})
                errors = []
                page.on("pageerror", lambda e: errors.append(str(e)))
                page.route("**/*", lambda route: route.continue_() if route.request.url.startswith("http://127.0.0.1:") else route.abort())
                page.goto(f"http://127.0.0.1:{server.server_port}/account-checks")
                page.locator("#monitor").fill("smoke-test-only")
                page.locator("#connect").click()
                page.locator("#content").wait_for(state="visible")
                page.locator("#source").select_option("upload")
                page.locator("#upload").set_input_files({"name": "accounts.json", "mimeType": "application/json",
                    "buffer": json.dumps({"email": "smoke@example.test", "sso": "test-sso-private"}).encode()})
                page.locator("#preview").click()
                page.wait_for_function("!document.getElementById('start').disabled")
                page.locator("#start").click()
                page.get_by_text("MISSING_THINKING", exact=True).wait_for()
                page.locator('[data-action="apply"]').click()
                page.wait_for_function("document.getElementById('results').textContent.includes('已应用')")
                assert "test-sso-private" not in page.content()
                assert "smoke@example.test" not in page.content()
                assert not errors, errors
                page.screenshot(path="/tmp/account-checks-desktop.png", full_page=True)
                page.set_viewport_size({"width": 390, "height": 844})
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "mobile overflow"
                page.screenshot(path="/tmp/account-checks-mobile.png", full_page=True)
                browser.close()
                print("Browser smoke passed: connect, upload, preview, check, apply, redaction, desktop/mobile layout.")
        finally:
            server.shutdown()
            thread.join(timeout=3)
            jobs.shutdown()


if __name__ == "__main__":
    main()
