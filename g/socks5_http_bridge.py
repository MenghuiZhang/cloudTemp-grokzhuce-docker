# -*- coding: utf-8 -*-
"""
本机 HTTP CONNECT 桥 → 上游 SOCKS5（带账号）。

Firefox / Camoufox / Playwright Firefox **不支持 SOCKS5 用户名密码**，
直接挂 socks5://user:pass@host 会启动后 page.goto 全超时。
curl_cffi 能走 SOCKS5 auth，浏览器不行。

方案：本机起一个无鉴权 HTTP 代理，CONNECT 时经 PySocks 连上游 SOCKS5。
Camoufox 只连 http://127.0.0.1:<port>。
"""
from __future__ import annotations

import select
import socket
import threading
import time
from typing import Any, Optional
from urllib.parse import unquote, urlparse

try:
    import socks  # PySocks
except Exception:  # pragma: no cover
    socks = None  # type: ignore


def parse_socks5_upstream(spec: str) -> Optional[dict[str, Any]]:
    """
    解析 socks5 / socks5h URL 或 host:port:user:pass。
    返回 {host, port, username, password}。
    """
    s = (spec or "").strip()
    if not s:
        return None
    host = port = user = pw = ""
    if "://" in s:
        u = urlparse(s)
        scheme = (u.scheme or "").lower()
        if scheme not in ("socks5", "socks5h", "socks4", "http", "https"):
            # 仍尝试当 socks
            pass
        host = u.hostname or ""
        port = int(u.port or 0)
        user = unquote(u.username or "")
        pw = unquote(u.password or "")
    elif "@" in s:
        cred, hp = s.rsplit("@", 1)
        if ":" in cred and ":" in hp:
            user, pw = cred.split(":", 1)
            host, port_s = hp.rsplit(":", 1)
            port = int(port_s)
    else:
        parts = s.split(":")
        if len(parts) >= 4 and parts[1].isdigit():
            host, port_s, user = parts[0], parts[1], parts[2]
            pw = ":".join(parts[3:])
            port = int(port_s)
        elif len(parts) == 2 and parts[1].isdigit():
            host, port = parts[0], int(parts[1])
        else:
            return None
    if not host or not port:
        return None
    return {
        "host": host,
        "port": int(port),
        "username": user or "",
        "password": pw or "",
    }


class Socks5HttpBridge:
    """
    单上游 sticky 的本机 HTTP CONNECT 桥。
    每条 1024 sid 开一个桥（不同本地端口），保证出口不串。
    """

    def __init__(
        self,
        upstream: dict[str, Any],
        *,
        bind: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        if socks is None:
            raise RuntimeError("需要 PySocks：pip install PySocks")
        self.upstream = upstream
        self.bind = bind
        self._port = int(port or 0)
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._started = False

    @property
    def port(self) -> int:
        return int(self._port)

    @property
    def local_http(self) -> str:
        return f"http://{self.bind}:{self._port}"

    @property
    def playwright_proxy(self) -> dict[str, str]:
        # 无账号，Firefox 可吃
        return {"server": f"http://{self.bind}:{self._port}"}

    def start(self) -> "Socks5HttpBridge":
        if self._started:
            return self
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.bind, self._port))
        srv.listen(64)
        srv.settimeout(1.0)
        self._port = int(srv.getsockname()[1])
        self._sock = srv
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._serve_loop,
            name=f"socks5-bridge-{self._port}",
            daemon=True,
        )
        self._thread.start()
        self._started = True
        return self

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        self._sock = None
        t = self._thread
        if t and t.is_alive():
            t.join(timeout=2.0)
        self._thread = None
        self._started = False

    def _serve_loop(self) -> None:
        while not self._stop.is_set():
            try:
                assert self._sock is not None
                client, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_client,
                args=(client,),
                daemon=True,
            ).start()

    def _handle_client(self, client: socket.socket) -> None:
        upstream_sock: Optional[socket.socket] = None
        try:
            client.settimeout(30.0)
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = client.recv(4096)
                if not chunk:
                    break
                data += chunk
            if not data:
                return
            first = data.split(b"\r\n", 1)[0].decode("utf-8", "replace")
            parts = first.split()
            if len(parts) < 2:
                client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                return
            method = parts[0].upper()
            target = parts[1]
            if method != "CONNECT":
                # 仅支持 HTTPS CONNECT（注册站全是 https）
                client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                return
            if ":" in target:
                host, port_s = target.rsplit(":", 1)
                try:
                    port = int(port_s)
                except ValueError:
                    host, port = target, 443
            else:
                host, port = target, 443

            up = self.upstream
            upstream_sock = socks.socksocket()
            upstream_sock.set_proxy(
                socks.SOCKS5,
                up["host"],
                int(up["port"]),
                True,  # rdns
                up.get("username") or None,
                up.get("password") or None,
            )
            upstream_sock.settimeout(30.0)
            upstream_sock.connect((host, port))
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            # 若头后面还粘了 body（少见），转过去
            rest = data.split(b"\r\n\r\n", 1)
            if len(rest) == 2 and rest[1]:
                try:
                    upstream_sock.sendall(rest[1])
                except Exception:
                    pass
            self._pipe(client, upstream_sock)
        except Exception:
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except Exception:
                pass
        finally:
            for s in (client, upstream_sock):
                try:
                    if s:
                        s.close()
                except Exception:
                    pass

    @staticmethod
    def _pipe(a: socket.socket, b: socket.socket) -> None:
        sockets = [a, b]
        try:
            a.setblocking(False)
            b.setblocking(False)
        except Exception:
            pass
        deadline = time.time() + 180.0
        while time.time() < deadline:
            try:
                r, _, x = select.select(sockets, [], sockets, 1.0)
            except Exception:
                break
            if x:
                break
            if not r:
                continue
            for s in r:
                other = b if s is a else a
                try:
                    data = s.recv(65536)
                except Exception:
                    return
                if not data:
                    return
                try:
                    other.sendall(data)
                except Exception:
                    return


# sid/spec → bridge（进程内复用，同 sticky 共用一个本地口）
_BRIDGES: dict[str, Socks5HttpBridge] = {}
_BRIDGES_LOCK = threading.Lock()


def ensure_socks5_http_bridge(spec_or_url: str) -> Optional[dict[str, str]]:
    """
    若是 socks5(+auth) → 返回给 Playwright 的 {server: http://127.0.0.1:port}
    非 socks5 → None（调用方用原 proxy）。
    """
    raw = (spec_or_url or "").strip()
    if not raw:
        return None
    low = raw.lower()
    is_socks = (
        low.startswith("socks5://")
        or low.startswith("socks5h://")
        or low.startswith("socks4://")
    )
    # host:port:user:pass 且环境指定 socks 时，调用方应已写成 socks5h URL
    if not is_socks:
        return None
    up = parse_socks5_upstream(raw)
    if not up:
        return None
    # 无账号的 socks5 Firefox 可直连，不必桥
    if not (up.get("username") or ""):
        return None
    if socks is None:
        raise RuntimeError(
            "SOCKS5 带账号需要本机桥，请 pip install PySocks"
        )
    key = f"{up['host']}:{up['port']}:{up.get('username')}:{up.get('password')}"
    with _BRIDGES_LOCK:
        br = _BRIDGES.get(key)
        if br is None or not br._started:
            br = Socks5HttpBridge(up).start()
            _BRIDGES[key] = br
        return dict(br.playwright_proxy)


def shutdown_all_bridges() -> None:
    with _BRIDGES_LOCK:
        items = list(_BRIDGES.values())
        _BRIDGES.clear()
    for br in items:
        try:
            br.stop()
        except Exception:
            pass
