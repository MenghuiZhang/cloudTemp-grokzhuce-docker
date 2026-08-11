"""邮箱服务类 - 适配 cloudflare_temp_email / freemail API"""
from __future__ import annotations

import os
import re
import string
import random
import threading
import time
from email.utils import getaddresses
from typing import Optional

import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# workers.dev 部分部署证书与主机名不完全匹配时放行
try:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


class EmailService:
    """
    优先适配 dreamhunter2333/cloudflare_temp_email：
      POST /api/new_address
      POST /admin/new_address（配置 FREEMAIL_ADMIN_KEY 时）
      GET  /api/mails?limit=&offset=
      DELETE /api/delete_address
    FREEMAIL_TOKEN 作为 x-custom-auth（站点密码），不是 JWT。
    FREEMAIL_ADMIN_KEY 作为 x-admin-auth（管理员密码）。
    每个邮箱会拿到独立 jwt，内部维护。
    """

    _shared_outlook_usage: dict[str, int] = {}
    _shared_outlook_map: dict[str, dict[str, str]] = {}
    _outlook_lock = threading.RLock()

    def __init__(self):
        load_dotenv(override=False)
        self.email_type = (os.getenv("EMAIL_TYPE") or "freemail").strip().lower()
        self.outlook_accounts_raw = (os.getenv("OUTLOOK_ACCOUNTS") or "").strip()
        try:
            self.outlook_alias_limit = max(
                1, int(os.getenv("OUTLOOK_ALIAS_LIMIT") or "5")
            )
        except ValueError:
            self.outlook_alias_limit = 5

        self._outlook_accounts = self._parse_outlook_accounts()
        self._outlook_token_cache: dict[str, tuple[str, float]] = {}
        self._outlook_token_lock = threading.Lock()

        self.worker_domain = self.normalize_domain(os.getenv("WORKER_DOMAIN") or "")
        self.freemail_token = (os.getenv("FREEMAIL_TOKEN") or "").strip()
        self.admin_key = (os.getenv("FREEMAIL_ADMIN_KEY") or "").strip()
        self.mail_domain = (os.getenv("FREEMAIL_DOMAIN") or "").strip()  # 邮箱后缀，如 kikru.xyz
        self.random_subdomain = (
            os.getenv("FREEMAIL_RANDOM_SUBDOMAIN") or ""
        ).strip().lower() in ("1", "true", "yes", "on")

        if self.email_type not in ("outlook", "outlook-hotmail") and not self.worker_domain:
            raise ValueError("Missing: WORKER_DOMAIN")

        self.base_url = f"https://{self.worker_domain}" if self.worker_domain else ""
        self._jwt_by_email: dict[str, str] = {}
        self._session = self._build_session()
        # 探测 API 风格：cf_temp | freemail
        self._api_style = (os.getenv("FREEMAIL_API_STYLE") or "auto").strip().lower()
        self._settings_cache: Optional[dict] = None

    def _parse_outlook_accounts(self) -> list[dict[str, str]]:
        accounts = []
        # .env 中的多行账号列表保存为字面量 \n，运行时还原。
        raw = (self.outlook_accounts_raw or "").replace("\\n", "\n")
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "----" in line:
                parts = [part.strip() for part in line.split("----")]
                email_addr = parts[0] if parts else ""
                password = parts[1] if len(parts) > 1 else ""
                refresh_token = parts[2] if len(parts) > 2 else ""
                client_id = parts[3] if len(parts) > 3 else ""
            elif ":" in line:
                parts = line.split(":", 1)
                email_addr = parts[0].strip()
                password = parts[1].strip()
                refresh_token = ""
                client_id = ""
            else:
                continue
            if email_addr and (password or (refresh_token and client_id)):
                accounts.append(
                    {
                        "email": email_addr,
                        "password": password,
                        "refresh_token": refresh_token,
                        "client_id": client_id,
                    }
                )
        return accounts

    @staticmethod
    def normalize_domain(domain: str) -> str:
        return (
            (domain or "")
            .replace("https://", "")
            .replace("http://", "")
            .strip()
            .rstrip("/")
        )

    @staticmethod
    def _build_session() -> requests.Session:
        s = requests.Session()
        s.verify = False
        # 系统代理 7897 常挂起导致超时：默认不信任环境代理；
        # 需要代理时设 FREEMAIL_USE_SYSTEM_PROXY=1
        use_proxy = (os.getenv("FREEMAIL_USE_SYSTEM_PROXY") or "").strip() in (
            "1",
            "true",
            "True",
            "yes",
        )
        s.trust_env = use_proxy
        retries = Retry(total=2, backoff_factor=0.4, status_forcelist=(502, 503, 504))
        adapter = HTTPAdapter(max_retries=retries)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        return s

    @classmethod
    def fetch_mail_domains(
        cls,
        worker_domain: Optional[str] = None,
        token: Optional[str] = None,
    ) -> dict:
        """
        从 cloudflare_temp_email 拉取可用邮箱域名列表。
        返回 {ok, domains, default_domains, selected, message, settings}
        """
        load_dotenv(override=True)
        domain = cls.normalize_domain(worker_domain or os.getenv("WORKER_DOMAIN") or "")
        auth = (token if token is not None else (os.getenv("FREEMAIL_TOKEN") or "")).strip()
        selected = (os.getenv("FREEMAIL_DOMAIN") or "").strip()
        if not domain:
            return {
                "ok": False,
                "domains": [],
                "default_domains": [],
                "random_subdomain_domains": [],
                "selected": selected,
                "message": "请先填写 WORKER_DOMAIN",
                "settings": {},
            }

        base = f"https://{domain}"
        session = cls._build_session()
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["x-custom-auth"] = auth
            headers["Authorization"] = f"Bearer {auth}"

        settings: dict = {}
        last_err = ""
        for path in (
            "/open_api/settings",
            "/api/open_settings",
            "/open_api/open_settings",
        ):
            try:
                res = session.get(base + path, headers=headers, timeout=15)
                if res.status_code == 200:
                    data = res.json()
                    if isinstance(data, dict):
                        settings = data
                        break
                last_err = f"{path} -> {res.status_code}"
            except Exception as e:
                last_err = str(e)

        if not settings:
            return {
                "ok": False,
                "domains": [],
                "default_domains": [],
                "random_subdomain_domains": [],
                "selected": selected,
                "message": f"拉取域名失败: {last_err or '无响应'}",
                "settings": {},
            }

        domains = []
        for key in ("domains", "defaultDomains", "randomSubdomainDomains"):
            val = settings.get(key) or []
            if isinstance(val, list):
                for d in val:
                    d = str(d).strip()
                    if d and d not in domains:
                        domains.append(d)

        defaults = [
            str(d).strip()
            for d in (settings.get("defaultDomains") or [])
            if str(d).strip()
        ]
        random_subdomain_domains = [
            str(d).strip()
            for d in (settings.get("randomSubdomainDomains") or [])
            if str(d).strip()
        ]
        if selected and selected not in domains and selected != "auto":
            # 仍展示当前已选，即使接口未返回
            domains.insert(0, selected)
        if not selected or selected == "auto":
            selected_out = "auto"
        else:
            selected_out = selected

        return {
            "ok": True,
            "domains": domains,
            "default_domains": defaults,
            "random_subdomain_domains": random_subdomain_domains,
            "selected": selected_out,
            "message": f"已拉取 {len(domains)} 个域名" if domains else "接口无域名列表",
            "settings": {
                "needAuth": settings.get("needAuth"),
                "enableUserCreateEmail": settings.get("enableUserCreateEmail"),
                "prefix": settings.get("prefix") or "",
                "minAddressLen": settings.get("minAddressLen"),
                "maxAddressLen": settings.get("maxAddressLen"),
                "randomSubdomainDomains": random_subdomain_domains,
                "randomSubdomainLength": settings.get(
                    "randomSubdomainLength"
                ),
            },
        }

    def _auth_headers(self, jwt: Optional[str] = None) -> dict:
        h = {"Content-Type": "application/json"}
        if self.freemail_token:
            # cloudflare_temp_email 站点密码
            h["x-custom-auth"] = self.freemail_token
            # 兼容部分 freemail 用 Bearer
            if not jwt:
                h["Authorization"] = f"Bearer {self.freemail_token}"
        if jwt:
            h["Authorization"] = f"Bearer {jwt}"
        return h

    def _admin_headers(self) -> dict:
        headers = self._auth_headers()
        headers["x-admin-auth"] = self.admin_key
        return headers

    def _random_name(self, n: int = 10) -> str:
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

    def create_email(self):
        """创建临时邮箱，返回 (jwt, email)"""
        if self.email_type in ("outlook", "outlook-hotmail"):
            return self._create_outlook_alias()

        style = self._api_style
        if style in ("auto", "cf_temp", "cloudflare"):
            result = self._create_cf_temp()
            if result[0] and result[1]:
                return result
            if style != "auto":
                return None, None
        return self._create_freemail_legacy()

    def _create_outlook_alias(self):
        accounts = self._outlook_accounts
        if not accounts:
            print("[-] 创建邮箱失败(outlook): 未配置 OUTLOOK_ACCOUNTS")
            return None, None

        with EmailService._outlook_lock:
            available = [
                acc
                for acc in accounts
                if EmailService._shared_outlook_usage.get(
                    acc["email"].lower(), 0
                )
                < self.outlook_alias_limit
            ]
            if not available:
                print(
                    "[-] 创建邮箱失败(outlook): "
                    f"所有账号已达加号地址上限 ({self.outlook_alias_limit})"
                )
                return None, None

            acc = min(
                available,
                key=lambda item: EmailService._shared_outlook_usage.get(
                    item["email"].lower(), 0
                ),
            )
            main_email = acc["email"]
            usage_key = main_email.lower()

            if "@" in main_email:
                username, domain = main_email.rsplit("@", 1)
            else:
                username, domain = main_email, "outlook.com"

            for _ in range(10):
                tag = self._random_name(8)
                alias_email = f"{username}+{tag}@{domain}"
                if alias_email.lower() not in EmailService._shared_outlook_map:
                    break
            else:
                print("[-] 创建邮箱失败(outlook): 无法生成唯一加号地址")
                return None, None

            EmailService._shared_outlook_usage[usage_key] = (
                EmailService._shared_outlook_usage.get(usage_key, 0) + 1
            )
            EmailService._shared_outlook_map[alias_email.lower()] = {
                **acc,
                "main_email": main_email,
            }
        return alias_email, alias_email

    def _fetch_outlook_verification_code(self, alias_email: str, max_attempts: int = 50, stop_event=None) -> Optional[str]:
        alias_key = alias_email.lower()
        with EmailService._outlook_lock:
            info = EmailService._shared_outlook_map.get(alias_key)
        if not info:
            for acc in self._outlook_accounts:
                main_email = acc["email"]
                if "@" not in main_email or "@" not in alias_email:
                    continue
                main_local, main_domain = main_email.lower().rsplit("@", 1)
                alias_local, alias_domain = alias_key.rsplit("@", 1)
                if (
                    alias_domain == main_domain
                    and alias_local.startswith(main_local + "+")
                ):
                    info = {**acc, "main_email": main_email}
                    break
        if not info:
            print(f"[-] Outlook 收码失败: 未找到 {alias_email} 对应的主账号凭据")
            return None

        main_email = info["main_email"]

        imap_server = os.getenv("OUTLOOK_IMAP_SERVER", "outlook.office365.com").strip()
        try:
            imap_port = int(os.getenv("OUTLOOK_IMAP_PORT", "993").strip())
        except ValueError:
            imap_port = 993

        import imaplib
        import email as email_pkg

        seen_msg_ids: set[str] = set()

        for attempt in range(max_attempts):
            if stop_event is not None and stop_event.is_set():
                return None

            try:
                mail = imaplib.IMAP4_SSL(imap_server, imap_port)
                self._authenticate_outlook_imap(mail, info)
                mail.select("INBOX", readonly=True)

                status, data = mail.search(None, "ALL")
                if status == "OK" and data and data[0]:
                    msg_nums = data[0].split()
                    recent_nums = msg_nums[-15:]
                    recent_nums.reverse()

                    for num in recent_nums:
                        if stop_event is not None and stop_event.is_set():
                            try:
                                mail.logout()
                            except Exception:
                                pass
                            return None

                        num_str = num.decode("utf-8") if isinstance(num, bytes) else str(num)
                        if num_str in seen_msg_ids:
                            continue

                        status_fetch, msg_data = mail.fetch(num, "(RFC822)")
                        if status_fetch != "OK" or not msg_data:
                            continue

                        raw_email = None
                        for response_part in msg_data:
                            if isinstance(response_part, tuple):
                                raw_email = response_part[1]
                                break

                        if not raw_email:
                            continue

                        msg = email_pkg.message_from_bytes(raw_email)
                        seen_msg_ids.add(num_str)
                        if not self._outlook_message_matches_alias(
                            msg, alias_email
                        ):
                            continue

                        subject = msg.get("Subject", "")
                        if subject:
                            try:
                                from email.header import decode_header
                                decoded_list = decode_header(subject)
                                subject_str = ""
                                for b, enc in decoded_list:
                                    if isinstance(b, bytes):
                                        subject_str += b.decode(enc or "utf-8", errors="ignore")
                                    else:
                                        subject_str += str(b)
                                subject = subject_str
                            except Exception:
                                pass

                        body_text = ""
                        body_html = ""

                        if msg.is_multipart():
                            for part in msg.walk():
                                ctype = part.get_content_type()
                                cdisp = str(part.get('Content-Disposition'))
                                if 'attachment' in cdisp:
                                    continue
                                payload = part.get_payload(decode=True)
                                if payload is None:
                                    payload = part.get_payload()
                                if payload:
                                    if isinstance(payload, bytes):
                                        charset = part.get_content_charset() or 'utf-8'
                                        try:
                                            text_content = payload.decode(charset, errors='ignore')
                                        except Exception:
                                            text_content = payload.decode('utf-8', errors='ignore')
                                    else:
                                        text_content = str(payload)
                                    if ctype == 'text/plain':
                                        body_text += text_content + "\n"
                                    elif ctype == 'text/html':
                                        body_html += text_content + "\n"
                        else:
                            payload = msg.get_payload(decode=True)
                            if payload is None:
                                payload = msg.get_payload()
                            if payload:
                                if isinstance(payload, bytes):
                                    charset = msg.get_content_charset() or 'utf-8'
                                    try:
                                        body_text = payload.decode(charset, errors='ignore')
                                    except Exception:
                                        body_text = payload.decode('utf-8', errors='ignore')
                                else:
                                    body_text = str(payload)

                        mail_dict = {
                            "subject": subject,
                            "text": body_text,
                            "html": body_html,
                            "from": msg.get("From", ""),
                            "to": msg.get("To", ""),
                        }

                        code = self._extract_code_from_mail(mail_dict)
                        if code:
                            try:
                                mail.logout()
                            except Exception:
                                pass
                            return code

                try:
                    mail.logout()
                except Exception:
                    pass

            except Exception:
                pass

            delay = 0.5 if attempt < 4 else 1.0
            if stop_event is not None:
                if stop_event.wait(timeout=delay):
                    return None
            else:
                time.sleep(delay)

        return None

    def _authenticate_outlook_imap(self, mail, account: dict[str, str]) -> None:
        """优先使用 OAuth2 XOAUTH2；没有 OAuth 凭据时兼容应用密码。"""
        main_email = account["main_email"]
        refresh_token = (account.get("refresh_token") or "").strip()
        client_id = (account.get("client_id") or "").strip()
        password = account.get("password") or ""

        if refresh_token and client_id:
            try:
                access_token = self._get_outlook_access_token(account)
                auth_string = (
                    f"user={main_email}\x01"
                    f"auth=Bearer {access_token}\x01\x01"
                ).encode("utf-8")
                mail.authenticate("XOAUTH2", lambda _challenge: auth_string)
                return
            except Exception as exc:
                if not password:
                    raise
                print(
                    f"[-] Outlook OAuth2 登录失败，尝试应用密码 "
                    f"({main_email}): {exc}"
                )

        if not password:
            raise ValueError(f"Outlook 账号缺少登录凭据: {main_email}")
        mail.login(main_email, password)

    def _get_outlook_access_token(self, account: dict[str, str]) -> str:
        main_email = account["main_email"].lower()
        now = time.time()
        with self._outlook_token_lock:
            cached = self._outlook_token_cache.get(main_email)
            if cached and cached[1] > now + 60:
                return cached[0]

            token_url = (
                os.getenv("OUTLOOK_TOKEN_URL")
                or "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
            ).strip()
            scope = (
                os.getenv("OUTLOOK_OAUTH_SCOPE")
                or "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"
            ).strip()
            response = requests.post(
                token_url,
                data={
                    "client_id": account["client_id"],
                    "grant_type": "refresh_token",
                    "refresh_token": account["refresh_token"],
                    "scope": scope,
                },
                timeout=20,
            )
            try:
                payload = response.json()
            except Exception:
                payload = {}
            access_token = str(payload.get("access_token") or "")
            if response.status_code != 200 or not access_token:
                detail = (
                    payload.get("error_description")
                    or payload.get("error")
                    or f"HTTP {response.status_code}"
                )
                raise RuntimeError(str(detail)[:300])

            try:
                expires_in = max(300, int(payload.get("expires_in") or 3600))
            except (TypeError, ValueError):
                expires_in = 3600
            self._outlook_token_cache[main_email] = (
                access_token,
                now + expires_in,
            )
            return access_token

    @staticmethod
    def _outlook_message_matches_alias(msg, alias_email: str) -> bool:
        """只处理发给当前 +tag 的邮件，避免并发任务串验证码。"""
        header_names = (
            "To",
            "Cc",
            "Delivered-To",
            "X-Original-To",
            "X-Envelope-To",
            "Envelope-To",
        )
        values = []
        for name in header_names:
            values.extend(msg.get_all(name, []))
        recipients = {
            address.lower()
            for _display_name, address in getaddresses(values)
            if address
        }
        return alias_email.lower() in recipients

    def _resolve_mail_domain(self) -> Optional[str]:
        """返回要使用的邮箱后缀；auto/空 则 None（由服务端默认）"""
        d = (self.mail_domain or os.getenv("FREEMAIL_DOMAIN") or "").strip()
        if not d or d.lower() == "auto":
            return None
        return d

    def _create_cf_temp(self):
        try:
            mail_domain = self._resolve_mail_domain()
            use_admin_api = bool(self.admin_key)
            create_path = "/admin/new_address" if use_admin_api else "/api/new_address"
            create_headers = self._admin_headers() if use_admin_api else self._auth_headers()
            for attempt in range(2):
                name = self._random_name(10 if attempt == 0 else 12)
                payload: dict = {"name": name}
                if mail_domain:
                    payload["domain"] = mail_domain
                if self.random_subdomain:
                    payload["enableRandomSubdomain"] = True
                res = self._session.post(
                    f"{self.base_url}{create_path}",
                    json=payload,
                    headers=create_headers,
                    timeout=20,
                )
                if res.status_code == 200:
                    data = res.json()
                    email = data.get("address") or data.get("email")
                    jwt = data.get("jwt") or data.get("token") or email
                    if email:
                        self._jwt_by_email[email] = jwt
                        self._api_style = "cf_temp"
                        return jwt, email
                # 名称冲突再试
                if res.status_code != 400:
                    api_kind = "admin" if use_admin_api else "api"
                    print(
                        f"[-] 创建邮箱失败(cf {api_kind}): "
                        f"{res.status_code} - {res.text[:200]}"
                    )
                    return None, None
            print(f"[-] 创建邮箱失败(cf): 重试后仍失败")
            return None, None
        except Exception as e:
            print(f"[-] 创建邮箱失败(cf): {e}")
            return None, None

    def _create_freemail_legacy(self):
        """旧 freemail: GET /api/generate + Bearer token"""
        try:
            res = self._session.get(
                f"{self.base_url}/api/generate",
                headers=self._auth_headers(),
                timeout=15,
            )
            if res.status_code == 200:
                email = res.json().get("email")
                if email:
                    self._jwt_by_email[email] = self.freemail_token
                    self._api_style = "freemail"
                    return email, email
            print(f"[-] 创建邮箱失败: {res.status_code} - {res.text[:200]}")
            return None, None
        except Exception as e:
            print(f"[-] 创建邮箱失败: {e}")
            return None, None

    def fetch_verification_code(self, email, max_attempts=50, stop_event=None):
        """
        轮询收件箱提取验证码。
        Outlook 加号地址走 IMAP；其他邮箱走 freemail API。

        重要：列表接口通常只有 subject/preview，必须再拉 /api/mail/{id} 详情，
        否则容易把邮件 ID、时间戳等 6 位数字误当成验证码。

        轮询策略：前几次快扫（0.4s），后面稳定在 0.7s，总窗口约 30s+。
        """
        if self.email_type in ("outlook", "outlook-hotmail"):
            return self._fetch_outlook_verification_code(
                email,
                max_attempts=max_attempts,
                stop_event=stop_event,
            )

        jwt = self._jwt_by_email.get(email) or self.freemail_token
        seen_ids: set[str] = set()
        for attempt in range(max_attempts):
            if stop_event is not None and stop_event.is_set():
                return None
            try:
                code = self._poll_code_once(email, jwt, seen_ids)
                if code:
                    return code
            except Exception:
                pass
            # 前 6 次 0.4s 快扫，之后 0.7s（比原来 1s 更快发现邮件）
            delay = 0.4 if attempt < 6 else 0.7
            if stop_event is not None:
                if stop_event.wait(timeout=delay):
                    return None
            else:
                time.sleep(delay)
        return None

    def _list_mails(self, email: str, jwt: str) -> list:
        """拉取收件箱列表（新邮件在前优先）。"""
        mails: list = []

        if self._api_style in ("auto", "cf_temp", "cloudflare"):
            res = self._session.get(
                f"{self.base_url}/api/mails",
                params={"limit": 20, "offset": 0},
                headers=self._auth_headers(jwt=jwt),
                timeout=15,
            )
            if res.status_code == 200:
                data = res.json()
                if isinstance(data, list):
                    mails = data
                elif isinstance(data, dict):
                    mails = (
                        data.get("results")
                        or data.get("data")
                        or data.get("mails")
                        or data.get("messages")
                        or []
                    )
                if mails:
                    return mails if isinstance(mails, list) else []

        res = self._session.get(
            f"{self.base_url}/api/emails",
            params={"mailbox": email},
            headers=self._auth_headers(jwt=jwt),
            timeout=15,
        )
        if res.status_code == 200:
            emails = res.json()
            if isinstance(emails, dict):
                emails = emails.get("results") or emails.get("emails") or emails.get("data") or []
            if isinstance(emails, list):
                return emails
        return []

    def _fetch_mail_detail(self, mail_id: str, jwt: str) -> Optional[dict]:
        """cloudflare_temp_email: GET /api/mail/{id} 拿全文。"""
        if not mail_id:
            return None
        for path in (
            f"{self.base_url}/api/mail/{mail_id}",
            f"{self.base_url}/api/mails/{mail_id}",
            f"{self.base_url}/api/message/{mail_id}",
        ):
            try:
                res = self._session.get(
                    path,
                    headers=self._auth_headers(jwt=jwt),
                    timeout=15,
                )
                if res.status_code == 200:
                    data = res.json()
                    if isinstance(data, dict):
                        # 有的实现包一层 {result: {...}}
                        inner = data.get("result") or data.get("data") or data
                        return inner if isinstance(inner, dict) else data
            except Exception:
                continue
        return None

    def _poll_code_once(self, email: str, jwt: str, seen_ids: set) -> Optional[str]:
        mails = self._list_mails(email, jwt)
        if not mails:
            return None

        # 优先处理看起来像验证码邮件的条目，再按列表顺序（通常新→旧）
        def rank(m: dict) -> int:
            blob = " ".join(
                str(m.get(k) or "")
                for k in ("subject", "from", "sender", "preview", "text")
            ).lower()
            score = 0
            for kw in ("x.ai", "xai", "grok", "verif", "code", "验证", "otp"):
                if kw in blob:
                    score += 2
            return -score  # 越小越优先

        ordered = sorted(
            [m for m in mails if isinstance(m, dict)],
            key=rank,
        )

        for mail in ordered:
            mail_id = str(mail.get("id") or mail.get("mail_id") or mail.get("messageId") or "")
            if mail_id and mail_id in seen_ids:
                # 已检查过仍无码，跳过
                continue

            # 1) 列表里若已有明确字段
            for key in ("verification_code", "code", "otp"):
                if mail.get(key):
                    code = self._normalize_code(str(mail[key]))
                    if code:
                        return code

            # 2) 拉详情（正文往往只在详情里）
            detail = None
            if mail_id:
                detail = self._fetch_mail_detail(mail_id, jwt)
                seen_ids.add(mail_id)

            combined = dict(mail)
            if isinstance(detail, dict):
                combined.update({k: v for k, v in detail.items() if v})

            code = self._extract_code_from_mail(combined)
            if code:
                return code

            # 没有 id 的邮件只扫一次摘要，避免死循环重复
            if not mail_id:
                code = self._extract_code_from_mail(mail)
                if code:
                    return code
        return None

    @staticmethod
    def _normalize_code(raw: str) -> Optional[str]:
        """规范化验证码：保留 x.ai 的 XXX-XXX，或纯 6 位数字。"""
        if not raw:
            return None
        s = raw.strip().upper()
        # Grok/x.ai 常见：MM0-SF3
        m = re.fullmatch(r"([A-Z0-9]{3})-([A-Z0-9]{3})", s)
        if m:
            return f"{m.group(1)}-{m.group(2)}"
        # 去掉空格/破折号后的 6 位数字
        digits = re.sub(r"\D", "", s)
        if re.fullmatch(r"\d{6}", digits):
            # 过滤明显不是验证码的占位/年份类
            if digits in {"000000", "123456", "111111", "177010"}:
                return None
            return digits
        # 无连字符的 6 位字母数字
        alnum = re.sub(r"[^A-Z0-9]", "", s)
        if re.fullmatch(r"[A-Z0-9]{6}", alnum) and not re.fullmatch(r"\d{6}", alnum):
            return f"{alnum[:3]}-{alnum[3:]}"
        return None

    def _mail_text(self, mail: dict) -> str:
        if not isinstance(mail, dict):
            return ""
        chunks: list[str] = []
        for key in (
            "subject",
            "text",
            "text_content",
            "textContent",
            "bodyPreview",
            "preview",
            "html",
            "content",
            "body",
            "raw",
            "message",
            "source",
        ):
            val = mail.get(key)
            if isinstance(val, str) and val.strip():
                chunks.append(val)
            elif isinstance(val, dict):
                for v in val.values():
                    if isinstance(v, str) and v.strip():
                        chunks.append(v)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        chunks.append(item)
                    elif isinstance(item, dict):
                        for v in item.values():
                            if isinstance(v, str):
                                chunks.append(v)
        text = "\n".join(chunks)
        # HTML → 粗略纯文本，避免标签/样式里的数字干扰
        if "<" in text and ">" in text:
            text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", text)
            text = re.sub(r"(?i)<br\s*/?>", "\n", text)
            text = re.sub(r"(?i)</p>", "\n", text)
            text = re.sub(r"(?s)<[^>]+>", " ", text)
            text = re.sub(r"[ \t\r\f\v]+", " ", text)
        return text

    def _extract_code_from_mail(self, mail: dict) -> Optional[str]:
        if not isinstance(mail, dict):
            return None

        for key in ("verification_code", "code", "otp"):
            if mail.get(key):
                code = self._normalize_code(str(mail[key]))
                if code:
                    return code

        text = self._mail_text(mail)
        if not text:
            return None

        # 1) x.ai / Grok 主格式：XXX-XXX（必须优先，不能当 6 位数字乱拆）
        for pat in (
            r"(?i)(?:verification\s*code|verify(?:\s*your)?\s*(?:email|code)?|your\s*code|code\s*is|验证码)\s*[:：\s]*([A-Z0-9]{3}-[A-Z0-9]{3})",
            r"(?<![A-Z0-9-])([A-Z0-9]{3}-[A-Z0-9]{3})(?![A-Z0-9-])",
            r"(?i)background-color:\s*#F3F3F3[^>]*>[\s\S]{0,80}?([A-Z0-9]{3}-[A-Z0-9]{3})",
        ):
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                code = self._normalize_code(m.group(1))
                if code:
                    return code

        # 2) 带明确文案的 6 位数字（禁止裸匹配任意 6 位，易把 124002 这类垃圾数字当码）
        labeled = [
            r"(?i)(?:verification\s*code|your\s*(?:verification\s*)?code(?:\s*is)?|code\s*is|one[-\s]?time(?:\s*code)?|otp|验证码)\s*[:：is\s]*(\d{6})\b",
            r"(?i)enter(?:\s+this)?(?:\s+code)?[^\d]{0,20}(\d{6})\b",
            r"(?i)>\s*(\d{6})\s*<",  # HTML 大号展示
        ]
        for pat in labeled:
            for m in re.finditer(pat, text):
                code = self._normalize_code(m.group(1))
                if code:
                    return code

        # 3) 主题行明确是验证码时再取 subject 中的 6 位
        subject = str(mail.get("subject") or "")
        if re.search(r"(?i)verif|code|otp|x\.?ai|grok|验证", subject):
            m = re.search(r"\b(\d{6})\b", subject)
            if m:
                code = self._normalize_code(m.group(1))
                if code:
                    return code

        # 不再做「任意 \b\d{6}\b」兜底——这正是误取 124002 的根源
        return None

    def delete_email(self, address):
        """删除邮箱"""
        if self.email_type in ("outlook", "outlook-hotmail"):
            # 加号地址不是服务端创建的真实别名，只释放本次运行的本地占用。
            alias_key = str(address or "").lower()
            with EmailService._outlook_lock:
                info = EmailService._shared_outlook_map.pop(alias_key, None)
                if info:
                    usage_key = info["main_email"].lower()
                    current = EmailService._shared_outlook_usage.get(
                        usage_key, 0
                    )
                    if current <= 1:
                        EmailService._shared_outlook_usage.pop(usage_key, None)
                    else:
                        EmailService._shared_outlook_usage[usage_key] = (
                            current - 1
                        )
            return True

        jwt = self._jwt_by_email.get(address) or self.freemail_token
        try:
            # cloudflare_temp_email
            res = self._session.delete(
                f"{self.base_url}/api/delete_address",
                headers=self._auth_headers(jwt=jwt),
                timeout=15,
            )
            if res.status_code == 200:
                self._jwt_by_email.pop(address, None)
                return True

            # 旧 freemail
            res = self._session.delete(
                f"{self.base_url}/api/mailboxes",
                params={"address": address},
                headers=self._auth_headers(jwt=jwt),
                timeout=15,
            )
            ok = res.status_code == 200 and (
                res.json().get("success") if res.headers.get("content-type", "").startswith("application/json") else True
            )
            if ok:
                self._jwt_by_email.pop(address, None)
            return bool(ok)
        except Exception:
            return False
