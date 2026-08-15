import asyncio
import unittest
from unittest.mock import AsyncMock, patch

import api_solver


class _FakeManager:
    def __init__(self, browser=None, start_error=None):
        self.browser = browser
        self.start_error = start_error
        self.closed = 0

    async def start(self):
        if self.start_error is not None:
            raise self.start_error
        return self.browser

    async def __aexit__(self, *_args):
        self.closed += 1


class _FakeBrowser:
    def __init__(self, context_error=None):
        self.context_error = context_error
        self.closed = 0

    def is_connected(self):
        return self.closed == 0

    async def new_context(self, **_kwargs):
        if self.context_error is not None:
            raise self.context_error
        raise AssertionError("test did not provide a context")

    async def close(self):
        self.closed += 1


def _bare_server():
    server = api_solver.TurnstileAPIServer.__new__(api_solver.TurnstileAPIServer)
    server.browser_type = "camoufox"
    server.headless = True
    server.debug = False
    server.proxy_support = False
    server.capture_dumps = False
    server.browser_pool = asyncio.Queue()
    server.browser_slots = {}
    server.background_tasks = set()
    server.periodic_cleanup_task = None
    server.closing = False
    server.browser_max_uses = 100
    return server


class SolverBrowserLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_each_camoufox_slot_has_its_own_manager(self):
        server = _bare_server()
        managers = []

        def manager_factory(**_kwargs):
            manager = _FakeManager(_FakeBrowser())
            managers.append(manager)
            return manager

        config = {
            "browser_name": "camoufox",
            "browser_version": "custom",
            "useragent": None,
            "sec_ch_ua": "",
        }
        with patch.object(api_solver, "AsyncCamoufox", side_effect=manager_factory):
            first = await server._create_browser_slot(1, config)
            second = await server._create_browser_slot(2, config)

        self.assertIsNot(first.manager, second.manager)
        await server._close_browser_slot(first)
        await server._close_browser_slot(second)
        self.assertEqual([manager.closed for manager in managers], [1, 1])

    async def test_1200_uses_recycle_every_100_without_growing_pool(self):
        server = _bare_server()
        created = []

        async def create_slot(index, config):
            browser = _FakeBrowser()
            manager = _FakeManager(browser)
            slot = api_solver.BrowserSlot(index, manager, browser, dict(config))
            created.append(slot)
            return slot

        server._create_browser_slot = create_slot
        config = {"useragent": None, "sec_ch_ua": ""}
        initial = await create_slot(1, config)
        server.browser_slots[1] = initial
        await server.browser_pool.put(initial)

        for _ in range(1200):
            slot = await server.browser_pool.get()
            await server._release_browser_slot(slot)
            while server.browser_pool.empty():
                await asyncio.sleep(0)

        self.assertEqual(server.browser_pool.qsize(), 1)
        self.assertEqual(len(server.browser_slots), 1)
        self.assertEqual(len(created), 13)  # initial + 12 deterministic rotations
        self.assertEqual(sum(x.browser.closed for x in created), 12)
        await server._shutdown()
        self.assertEqual(sum(x.browser.closed for x in created), 13)

    async def test_context_setup_failure_rebuilds_bad_slot(self):
        server = _bare_server()
        bad_browser = _FakeBrowser(context_error=RuntimeError("new_context failed"))
        bad_manager = _FakeManager(bad_browser)
        bad_slot = api_solver.BrowserSlot(
            1,
            bad_manager,
            bad_browser,
            {"useragent": None, "sec_ch_ua": ""},
        )
        server.browser_slots[1] = bad_slot
        await server.browser_pool.put(bad_slot)

        replacement = api_solver.BrowserSlot(
            1,
            _FakeManager(_FakeBrowser()),
            _FakeBrowser(),
            {"useragent": None, "sec_ch_ua": ""},
        )
        # Keep manager/browser paired for cleanup assertions.
        replacement.manager.browser = replacement.browser
        server._create_browser_slot = AsyncMock(return_value=replacement)

        with patch.object(api_solver, "save_result", new=AsyncMock()):
            await server._solve_turnstile("task", "https://example.test", "key")
            while server.browser_pool.empty():
                await asyncio.sleep(0)

        self.assertEqual(bad_browser.closed, 1)
        self.assertEqual(bad_manager.closed, 1)
        self.assertIs(await server.browser_pool.get(), replacement)
        await server._shutdown()


if __name__ == "__main__":
    unittest.main()
