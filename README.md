# Grok 批量注册工具

Web 控制台 + same-session 注册引擎，支持临时邮箱、Turnstile、Castle 同页 mint，以及 HTTP 导入 sub2api。

## 功能

- 同页 same-session 注册（Castle mint + 页内 fetch，默认 CLEAN 主路径）
- 临时邮箱自动建邮 / 收码（[cloudflare_temp_email](https://github.com/dreamhunter2333/cloudflare_temp_email)）
- 本地 Camoufox Turnstile Solver（也可接 YesCaptcha）
- 多线程并发；主流程 / Risk·Token·NSFW 双栏日志
- 进度按 CLEAN 成功数计；创邮次数单独展示（数量 = 创邮次数停批）
- 注册成功后页面「导入」入库 sub2api（HTTP Admin API / sso-to-oauth；`AUTO_IMPORT=1` 可开自动）
- 按**分组名称**自动解析 sub2api `group_id`（ID 只读缓存）
- 配置页支持注册代理格式校验与连通性测试（出口 IP/地区 + accounts.x.ai）

## 目录结构

```
.
├── app.py                      # Web 控制台（Flask）
├── grok.py                     # 注册引擎 + CLI
├── solver_manager.py           # Turnstile Solver 进程管理
├── api_solver.py               # 本地 Turnstile Solver
├── setup_solver.py             # 安装 Solver / camoufox 依赖
├── import_batch_once.py        # 从 keys 文本批量导入 sub2api
├── standalone_same_session_n.py # 同会话批跑脚本（本地/池代理）
├── browser_configs.py
├── db_results.py
├── templates/index.html        # 控制台前端
├── g/                          # 邮箱 / Turnstile / Castle / 同会话 / 导入
├── .env.example
└── requirements.txt
```

本地运行产生、**不要提交**的内容：

- `.env`（真实密钥）
- `keys/`（SSO TXT 输出，以及每次任务对应的 `*_accounts.json` 结构化账号文件）
- `logs/`（运行日志）
- `proxies/`（个人代理清单）

## 环境要求

- Python 3.10+
- Windows / Linux 均可（Camoufox Solver 在 Windows 上更常用）
- 已部署的 [cloudflare_temp_email](https://github.com/dreamhunter2333/cloudflare_temp_email) Worker
- 可选：自建 sub2api 用于账号入库

## 安装

### Docker（推荐）

```bash
cp .env.example .env
# 编辑 .env，填写邮箱服务等实际配置
docker compose up -d --build
```

首次构建会下载 Camoufox 浏览器。容器健康后打开
`http://127.0.0.1:3333`。运行产物会持久化到宿主机的 `keys/`、
`logs/`、`register_sso/` 和 `converted_auth/`。

```bash
docker compose ps
docker compose logs -f
docker compose down
```

### 本地 Python

```bash
pip install -r requirements.txt
# 首次使用本地 Turnstile Solver
python setup_solver.py
```

## 配置

```bash
cp .env.example .env
```

编辑 `.env`（**切勿提交**）：

| 配置项 | 说明 | 默认 |
|--------|------|------|
| `WORKER_DOMAIN` | cloudflare_temp_email 的 Worker 域名（不要 `https://`） | — |
| `FREEMAIL_TOKEN` | 站点密码 / JWT | — |
| `FREEMAIL_ADMIN_KEY` | `ADMIN_PASSWORDS` 中的管理员密码；填写后通过 `/admin/new_address` 建邮；与站点密码相同时可填 `${FREEMAIL_TOKEN}` | 空 |
| `FREEMAIL_DOMAIN` | 邮箱后缀；`auto` 用服务端默认 | `auto` |
| `FREEMAIL_RANDOM_SUBDOMAIN` | `1` 时通过原生 `enableRandomSubdomain` 创建随机子域邮箱 | `0` |
| `FREEMAIL_API_STYLE` | `auto` / `cf_temp` / `freemail` | `auto` |
| `EMAIL_TYPE` | `freemail` 或 `outlook-hotmail`（Outlook 加号地址） | `freemail` |
| `OUTLOOK_ACCOUNTS` | Outlook 账号；每行 `email:应用密码`，或 `email----应用密码----refresh_token----client_id` | 空 |
| `OUTLOOK_ALIAS_LIMIT` | 每个 Outlook 主账号在一次运行中分配的加号地址上限 | `5` |
| `YESCAPTCHA_KEY` | 有则走 YesCaptcha；空则本地 Solver | 空 |
| `SOLVER_URL` | 本地 Solver 地址 | `http://127.0.0.1:5072` |
| `SOLVER_BROWSER` | `camoufox` / `chromium` | `camoufox` |
| `SOLVER_THREADS` | Solver 浏览器线程 | `4` |
| `UI_HOST` / `UI_PORT` | Web 监听 | `127.0.0.1` / `3333` |
| `GROK_PROXY` | 注册代理；空=直连。支持 `host:port` / URL / `user:pass@host:port` / `host:port:user:pass` | 空 |
| `SUB2API_URL` | sub2api 根地址 | `http://127.0.0.1:9898` |
| `SUB2API_GROK_GROUP_NAME` | 导入目标分组**名称**（按名称解析 ID） | `grok` |
| `SUB2API_GROK_GROUP_ID` | 可选缓存；运行时会按名称回写 | 空 |
| `UPSTREAM_ADMIN_EMAIL` | sub2api 管理员邮箱 | — |
| `UPSTREAM_ADMIN_PASSWORD` | sub2api 管理员密码 | — |

说明：

- Outlook 模式生成 `主账号+随机标签@outlook.com`，邮件仍进入主账号收件箱；这不是微软账户中创建的真实别名。
- Outlook 收件优先使用 OAuth2；只有账号行未提供 OAuth2 凭据时，才尝试密码或应用密码。使用前需在 Outlook.com 中启用 IMAP。
- Cloudflare 随机子域模式必须选择 Worker `RANDOM_SUBDOMAIN_DOMAINS` 中的基础域名；Worker 还需配置 `RANDOM_SUBDOMAIN_LENGTH`。Cloudflare DNS 必须为基础域名配置通配 `*` MX 并指向相同邮件路由，否则地址可以创建但无法收件。
- 页面「配置」里只填**分组名称**；分组 ID 只读显示，保存/测试/导入时自动拉取。
- 名称匹配的是 sub2api **已有**分组（可跨 platform）；新分组请先在 sub2api 后台创建。
- 导入主路径：`POST /api/v1/admin/grok/sso-to-oauth`（服务端换票）。
- 默认**不**自动入库；需要自动时在 `.env` 设 `AUTO_IMPORT=1`。
- Token 换票 / 协议 / NSFW 在成功后异步后台跑，不堵注册主路径。

## 使用

### 1. 启动 Solver（本地模式）

```bash
python solver_manager.py start
python solver_manager.py status
```

Web 控制台也可一键启动。

### 2. Web 控制台（推荐）

```bash
python start.py
```

`start.py` 会自动创建/复用 `.venv`；未配置 `YESCAPTCHA_KEY` 时，会先启动并等待本地 Solver 就绪。Web 退出后，只会停止本次由启动器新建的 Solver。首次安装浏览器依赖使用 `python start.py --setup-solver`；如需跳过预启动可加 `--no-solver`。

打开：`http://127.0.0.1:3333`

- **配置**：邮箱 / Solver / 注册代理（可测出口与 x.ai）/ sub2api / 分组名称 → 写入 `.env`
- **运行**：选择 `same_session`、并发、数量后开始
- **日志**：左侧主流程（建邮→camoufox→signup→SSO），右侧 Risk / Token / NSFW
- **Keys**：下载 SSO 文件，一键导入 sub2api

same_session 建议并发先 **1～2**（注册浏览器 + Solver 双开）。

### 3. 命令行

```bash
python grok.py
```

成功账号写入 `keys/`。

### 4. 批量导入已有 SSO 文件

```bash
python import_batch_once.py keys/your_sso.txt
```

### 5. 注册 JSON 转 CPA / sub2api JSON

读取 `register_sso/` 中每个 JSON 的 `sso`，完成 xAI OAuth 换票后，同时输出
CLIProxyAPI（CPA）可加载的 `type=xai` 单账号文件和 sub2api 可导入的合并文件：

```bash
python convert_sso_json.py
```

输出默认保存在 `converted_auth/`，其中 CPA 单账号文件位于
`converted_auth/cpa/`，sub2api 合并文件位于 `converted_auth/sub2api/`。常用参数：

```bash
# 只扫描校验，不联网
python convert_sso_json.py --dry-run

# 默认强制直连；先用 1 个账号验证
python convert_sso_json.py --direct --limit 1

# 默认 8 路并发，并自动复用 converted_auth/cpa/ 中已有结果继续跑
python convert_sso_json.py --direct --workers 8

# 如确实需要代理，再显式指定
python convert_sso_json.py --proxy http://127.0.0.1:7890 --limit 10

# 只生成 sub2api 文件，并写入目标分组 ID
python convert_sso_json.py --format sub2api --group-id 3
```

SSO cookie 不能直接作为 CPA OAuth 凭证；正常转换会访问 xAI 完成 device flow，
因此需要网络可达，且可能受到账号状态和限流影响。输出文件含访问令牌，请勿提交或分享。
遇到 `rate_limited` 时可将 `--workers` 降为 `4`；如需忽略已有 CPA 缓存并重新换票，
使用 `--refresh-existing --overwrite`。换票返回 `invalid_grant: Access denied` 时，
原始账号 JSON 会自动移入 `register_sso/失败/`；可用 `--failed-dir` 指定其他目录。

## 注册路径

| 模式 | 说明 |
|------|------|
| `same_session`（默认） | 同页 Castle mint + 页内发码/验码/signup，CLEAN 主路径 |
| `protocol` / `legacy` | 兼容旧路径，易被 Castle deny，不推荐 |

## 注意事项

- 仅供学习与自用自动化，请遵守目标站点与服务条款。
- 仓库不包含真实 `.env`、代理账号、邮箱密码、keys/logs。
- 推送前请确认工作区无个人域名、代理凭证与内网地址。
