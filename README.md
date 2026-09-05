# Grok 批量注册工具

Web 控制台 + same-session 注册引擎，支持临时邮箱、Turnstile、Castle 同页 mint，以及 Sub2API、CLIProxyAPI（CPA）和 grok2api 多目标导入。

> v1.5.1 修复发布镜像的运行时漂移：正式镜像继承 v1.4.0 已验证的
> Camoufox、浏览器和 Python 依赖层，再覆盖 v1.5 应用代码。开发用
> `Dockerfile` 保持独立，正式发布使用 `Dockerfile.release`。

## 功能

- 同页 same-session 注册（Castle mint + 页内 fetch，默认 CLEAN 主路径）
- 独立邮箱配置中心：Outlook Plus Alias、[idinging/freemail](https://github.com/idinging/freemail)、[YYDS Mail](https://vip.215.im/docs)、[cloudflare_temp_email](https://github.com/dreamhunter2333/cloudflare_temp_email)
- Cloudflare Temp 多基础域名顺序轮替、即时列表替换与随机子域
- 本地 Camoufox Turnstile Solver（也可接 YesCaptcha）
- 多线程并发；主流程 / Risk·Token·NSFW 双栏日志
- Risk 开启时按 `Risk → PENDING_BFS → OAuth/BFS → 账号检测` 分类；Risk 关闭时不执行 Risk、OAuth、BFS 或真实聊天检测，账号归入 `UNCHECKED`
- 批次目标统一按“成功创建邮箱数”计；创邮失败不占目标，已创邮的在途账号会继续完成分类
- 统一互斥分类文件：`*_clean.txt` / `*_marked.txt` / `*_review.txt` / `*_unchecked.txt` / `*_infra_retry.txt`
- 独立账号检测中心：新账号后台自动检测、历史账号多来源批量复检、脱敏报告与手动应用
- Risk MARKED 节点阶梯冷却（1 / 5 / 15 / 30 分钟）；仅明确 Risk CLEAN 重置该节点阶梯
- 独立导入中心：最近成功 / Keys / 注册 JSON / 上传文件，多目标预览、后台任务和失败重试
- CPA/OIDC 本地生成与 CLIProxyAPI 上传；grok2api 本地池、chenyme Web/Console/Build、jiujiu 兼容
- 每个下游独立测试、代理和自动导入开关；默认全部关闭
- 按**分组名称**自动解析 sub2api `group_id`（ID 只读缓存）
- 独立“注册代理”页支持最多 10,000 条代理，按账号锁定租约、轮询/随机/最少占用调度、冷却和批量健康检查

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
├── templates/email_settings.html # 独立邮箱配置页
├── templates/import_services.html # 独立导入中心
├── g/import_services.py        # 导入配置、目标适配器与后台任务
├── g/                          # 邮箱 / Turnstile / Castle / 同会话 / 导入
├── .env.example
└── requirements.txt
```

本地运行产生、**不要提交**的内容：

- `.env`（真实密钥）
- `keys/`（SSO TXT 输出，以及每次任务对应的 `*_accounts.json`、`*_clean.txt`、`*_unchecked.txt` 等文件）
- `logs/`（运行日志）
- `proxies/`（个人代理清单）

## 环境要求

- Python 3.10+
- Windows / Linux 均可（Camoufox Solver 在 Windows 上更常用）
- 至少一种可用邮箱服务（Outlook、Freemail、YYDS 或 Cloudflare Temp）
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

Compose 默认只把端口绑定到宿主机 `127.0.0.1`，并为项目创建独立的
`<项目名>_private` bridge 网络。该网络仍可访问互联网；不要设为
`internal: true`。如需修改宿主机端口，可通过单独的 Compose 环境变量传入：

```bash
GROK_HOST_PORT=3334 docker compose up -d --build
```

```bash
docker compose ps
docker compose logs -f
docker compose down
```

从旧版本升级时可直接保留原 `.env` 和现有 volume：程序会兼容读取旧邮箱变量；进入邮箱配置页保存后会写入新结构并保留旧变量用于回滚。默认部署是单进程、线程并发；不要用多个 Web worker 或多个容器共享同一 `.env`/`keys` volume。

Linux 服务器的正式/测试双实例、私有 GHCR 镜像、接入现有 1Panel 反代、
健康检查回滚、日志轮转和加密异地备份流程见
[`deploy/README.md`](deploy/README.md)。服务器部署参数放在
`deploy/deploy.env`，应用秘密仍只放在根目录 `.env`；两者不能混用。

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

推荐启动 Web 后访问 `http://127.0.0.1:3333/email-settings` 配置。邮箱密钥只写不读，页面留空表示保留现值；保存草稿、连接测试和启用服务是三个独立操作。

核心邮箱变量（完整清单见 `.env.example`）：

| 配置项 | 说明 | 默认 |
|--------|------|------|
| `EMAIL_PROVIDER` | `outlook` / `freemail` / `yyds` / `cloudflare_temp`；新安装先在页面测试并启用 | 空 |
| `EMAIL_TIMEOUT_SECONDS` | 收码总超时，范围 30～600 秒 | `120` |
| `EMAIL_PROXY_MODE` | `direct` / `register` / `custom` / `system` | `direct` |
| `EMAIL_TLS_VERIFY` | 是否严格验证邮箱 API 的 TLS 证书 | `1` |
| `EMAIL_OUTLOOK_ACCOUNTS_JSON` | Outlook 账号池 JSON；支持每账号 `alias_limit` | `[]` |
| `EMAIL_FREEMAIL_BASE_URL` | idinging/freemail API 地址 | 空 |
| `EMAIL_YYDS_API_KEY` | YYDS Mail 的 `AC-...` API Key | 空 |
| `EMAIL_CF_TEMP_BASE_URL` | cloudflare_temp_email Worker 地址 | 空 |
| `EMAIL_CF_TEMP_DOMAINS_JSON` | 按顺序轮替的基础域名 JSON 数组 | `[]` |
| `EMAIL_CF_TEMP_AUTO_DOMAIN` | `1` 时由服务端自动选域；显式域名池轮替不生效 | `1` |
| `EMAIL_CF_TEMP_RANDOM_SUBDOMAIN` | 传递原生 `enableRandomSubdomain` | `0` |
| `YESCAPTCHA_KEY` | 有则走 YesCaptcha；空则本地 Solver | 空 |
| `SOLVER_URL` | 本地 Solver 地址 | `http://127.0.0.1:5072` |
| `SOLVER_BROWSER` | `camoufox` / `chromium` | `camoufox` |
| `SOLVER_THREADS` | Solver 浏览器线程 | `4` |
| `SOLVER_BROWSER_MAX_USES` | 单个 Solver 浏览器处理指定次数后自动轮换 | `100` |
| `SOLVER_IDLE_SHUTDOWN_SECONDS` | 注册批次结束后空闲多久停止本地 Solver；`0` 为关闭 | `60` |
| `SOLVER_CAPTURE_DUMPS` | 保存 FO/RCH 诊断抓包；仅排障时开启 | `0` |
| `SOLVER_CAPTURE_MAX_GROUPS` / `SOLVER_CAPTURE_MAX_MB` | 抓包保留组数/总容量双上限 | `20` / `50` |
| `LOG_MAX_MB` / `LOG_ROTATE_FILE_COUNT` | 单份日志上限/总文件数（含当前） | `10` / `3` |
| `UI_HOST` / `UI_PORT` | Web 监听 | `127.0.0.1` / `3333` |
| `data/proxy_pool.json` | 注册代理池的本地私密存储；由 `/proxy-settings` 管理，不提交 Git | 空池（直连） |
| `data/domain_pool.json` | Cloudflare Temp 基础域名状态和审计历史；不提交 Git | 从现有域名配置迁移 |
| `MONITOR_TOKEN` | BFS 运维 API 的 Bearer / `X-Monitor-Token` | 必须显式配置 |
| `SUB2API_URL` | 旧版 sub2api 根地址；首次进入导入中心时用于迁移 | `http://127.0.0.1:9898` |
| `SUB2API_GROK_GROUP_NAME` | 导入目标分组**名称**（按名称解析 ID） | `grok` |
| `SUB2API_GROK_GROUP_ID` | 可选缓存；运行时会按名称回写 | 空 |
| `UPSTREAM_ADMIN_EMAIL` | sub2api 管理员邮箱 | — |
| `UPSTREAM_ADMIN_PASSWORD` | sub2api 管理员密码 | — |

说明：

- 旧 `EMAIL_TYPE`、`FREEMAIL_*`、`OUTLOOK_*` 会自动读取；新页面首次保存后写入新结构并继续双写兼容变量。
- Outlook 模式生成 `主账号+随机标签@outlook.com`，邮件仍进入主账号收件箱；这不是微软账户中创建的真实别名。
- Outlook 收件优先使用 OAuth2；只有账号行未提供 OAuth2 凭据时，才尝试密码或应用密码。使用前需在 Outlook.com 中启用 IMAP。
- Cloudflare Temp 域名表支持从服务拉取并镜像替换、去重、启停、诊断测试、筛选、分页和永久删除。非空列表保存后新域立即启用，缺失的旧域停用但保留历史；拉取失败或空列表不修改现有池。诊断测试不再影响启用状态。Risk MARKED 不停用或复验域名，下一次创邮按顺序轮询。
- Cloudflare 随机子域模式只应搭配 Worker `RANDOM_SUBDOMAIN_DOMAINS` 中的基础域名；Worker 还需配置 `RANDOM_SUBDOMAIN_LENGTH` 和通配 MX。
- Sub2API 配置已迁移到独立“导入服务”页面；分组 ID 在测试/导入时按名称自动解析。
- 名称匹配的是 sub2api **已有**分组（可跨 platform）；新分组请先在 sub2api 后台创建。
- 导入主路径：`POST /api/v1/admin/grok/sso-to-oauth`（服务端换票）。
- 默认**不**自动导入；服务测试通过后，可在导入中心按目标开启注册后自动导入。
- 导入配置和写入型密钥保存在 `data/import_services.json`，API 只返回掩码；旧版
  `converted_auth/import_services.json` 会在首次读取时自动迁移且保留原文件。
- Risk CLEAN 后先异步换票并检查 JWT `bfs` claim，再执行账号检测；完整检测 CLEAN 后才自动导入。
- JWT 中只要存在 `bfs` key（包括 `bfs: 0`）就是 MARKED；已取得但无法解码的 token 按 BFS UNKNOWN 处理。
- BFS MARKED/UNKNOWN 的 CPA 仅保留在本地且强制 `disabled=true`，不进入任何下游；注册路径中 BFS UNKNOWN 归入 REVIEW。

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

- **邮箱配置**：独立页面管理 provider、凭据、域名池、测试与启用
- **导入服务**：独立页面管理 Sub2API、CLIProxyAPI 和 grok2api，地址为 `/import-services`
- **账号检测**：独立页面选择来源、后台检测、查看与应用结果，地址为 `/account-checks`
- **配置**：Solver 等通用参数 → 写入 `.env`
- **日志与磁盘保护**：抓包默认关闭；可查看占用、调整保留上限并清理历史诊断抓包
- **注册代理**：独立页面管理代理池、调度与健康状态 → 写入 `data/proxy_pool.json`
- **域名管理**：Cloudflare Temp 区域管理基础域列表、启停、诊断测试和审计 → 写入 `data/domain_pool.json`
- **运行**：选择 `same_session`、并发、数量和本批 Risk 检测开关后开始
- **日志**：左侧主流程（建邮→camoufox→signup→SSO），右侧 Risk / Token / NSFW
- **Keys**：下载 SSO 文件；批量导入统一在导入中心执行

same_session 建议并发先 **1～2**（注册浏览器 + Solver 双开）。

关闭“启用账号 Risk 检测”后，Turnstile 和 Castle 仍作为注册必需步骤，
但 SSO 到手后不再执行 Risk、OAuth 或 BFS。`UNCHECKED` 只能进入 SSO Web/Console 目标，
不能手动升级为 CPA、Sub2API 或 Build 等 OAuth 目标。

### 3. 导入服务中心

打开 `http://127.0.0.1:3333/import-services`：

1. 在顶部服务卡片中保存并测试 Sub2API、CLIProxyAPI 或 grok2api。
2. 从最近成功、`keys/*.txt`、`register_sso/*.json` 或本地上传选择来源并预览。
3. 勾选一个或多个目标，创建后台任务；页面会按“账号 × 目标”显示结果。
4. 网络/5xx 会有限重试；鉴权和格式错误直接失败，可在任务结束后仅重试失败项。

CPA 文件写入 `converted_auth/cpa/`，grok2api 本地池写入
`converted_auth/grok2api/token.json`，脱敏任务历史写入 `logs/import_jobs/`。
Docker 内访问宿主机服务时不要使用 `127.0.0.1`，应填写
`host.docker.internal` 或 Compose 网络中的服务名。

### 4. 命令行

```bash
python grok.py
```

成功账号写入 `keys/`。

### 5. 批量导入已有 SSO 文件

```bash
python import_batch_once.py keys/your_sso.txt
```

### 6. 注册 JSON 转 CPA / sub2api JSON

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

### 7. 历史 CPA BFS 扫描

必须先预览，再对指定报告 apply；报告不包含 token：

```bash
python scan_bfs_auth.py preview
python scan_bfs_auth.py apply data/bfs_scans/bfs-scan-YYYYMMDD_HHMMSS-xxxxxxxx.json
```

Apply 只更新 CPA JSON 的 BFS 元数据和 `disabled`，不改写历史批次 TXT。经人工复核后，
可对 BFS MARKED/UNKNOWN 文件执行与当前 token SHA-256 绑定的放行：

```bash
python scan_bfs_auth.py override converted_auth/cpa/xai-example.json --reason "manual review"
```

Risk MARKED 不允许这种放行；token 更换后旧指纹自动失效。

## 账号检测中心

打开 `/account-checks`，输入现有 `.env` 中的 `MONITOR_TOKEN`。首次未设置该值时，
添加一个随机管理令牌并重启 Web 服务。页面令牌只在当前页内存保留，所有检测数据和写入 API 都要求鉴权。

默认无需配置聊天服务：使用 `https://cli-chat-proxy.grok.com/v1/chat/completions`、
模型 `grok-4.5` 和账号 OAuth token。模型及端点可在页面“可选设置”中调整。
账号文件自带的 `base_url`、HTTP headers 不会覆盖管理员设置，跨域重定向不会携带凭据跟随。
该端点的可达性和模型支持由 xAI 决定；404、模型不支持等进入 REVIEW，不作为账号封禁证据。

1. 选择最近注册、Keys TXT、注册 JSON、批次 `*_accounts.json`、CPA JSON 或上传 TXT/JSON；预览会去重，每批最多 2000 个账号。
2. “完整检测”对有 SSO 的账号先执行 Risk，必要时通过现有 OAuth 流程换票，再检查 BFS、网页辅助信号和真实流式回复。
   只有 OAuth 的 CPA 可执行 BFS 和聊天检测；不把缺少 SSO 当成账号异常。
3. 真实聊天默认并发 2、单次超时 90 秒、最多 256 输出 tokens。没有 thinking、输出不足 32 tokens、缺少 usage 或 TPS 异常只提示复核，不能证明模型降智。
4. “仅本地 BFS”不会联网或换票。没有 bfs 仅表示本地检查未发现该字段，结果仍为 UNCHECKED；不会据此放行完整检测。
5. 新注册账号在现有后台 enrich 池完成检测，CLEAN 后单独排队自动导入。批次结束后仍有后台工作时禁止启动新批次，避免串写输出文件。
6. 历史任务先生成报告，点击“应用结果”后才更新本地状态。Apply 会验证原始凭据版本，跳过已换票、已应用或被更新报告覆盖的记录。

| 状态 | 含义与处理 |
| --- | --- |
| CLEAN | 检测通过，可自动导入 |
| MARKED | BFS 字段存在，或明确 deny / 账号权限错误得到确认；禁止导入 |
| REVIEW | 单独 botFlag、样本不足、质量信号、额度/限流或结果不一致；暂停导入，复检后再应用 |
| INFRA_RETRY | 网络、代理或服务错误；暂停导入，可稍后复检 |
| UNCHECKED | 缺凭据、未完整检测或关闭自动检测；不自动导入 |

401 尝试刷新一次 OAuth；明确账号权限 403 和质量异常复测一次；网络/5xx 最多重试两次。
429 尊重 `Retry-After`：不超过 60 秒时等待后重试一次，较长时间交给后续复检；当前进程会阻止同账号在该等待期内再次发起检测。
错误重试保持同一出口，不通过更换代理绕过限流或权限拒绝。选择出口时优先账号原代理（历史动态代理模板只能恢复配置，不能保证原会话出口），再使用当前池，无可用代理则直连。

检测设置保存在 `data/account_checks_config.json`；脱敏报告在 `data/account_checks/`，
最多保留 100 个已结束任务或 30 天；重启中的任务标为 `interrupted`，不自动重放请求。
导入门禁状态保存在 `data/account_check_states.json`，以凭据 SHA-256 关联，不因报告过期而自动解除异常。
检测期间换票/刷新得到的新凭据单独以 0600 权限保存于 `data/account_check_credentials/`，Apply 时用于更新原始账号记录，
报告与 API 不包含完整邮箱、SSO/OAuth、代理密码或聊天正文。这些目录均已加入 Git 忽略规则。

Apply 只修改本地记录和分类旁文件，不删除账号，不撤销已导入的远端账号。
仅由本功能禁用的本地记录才会在后续 CLEAN 应用时恢复；已有的人工禁用会保留。

## 测试

自动化测试不读取真实邮箱密钥，也不调用公网服务：

```bash
python3 -m unittest discover -s tests -v
```

真实凭据与自建实例请在“邮箱服务配置”页面主动点击测试；Cloudflare Temp 可选择逐域创建并清理测试邮箱。

## 注册路径

| 模式 | 说明 |
|------|------|
| `same_session`（默认） | 同页 Castle mint + 页内发码/验码/signup，CLEAN 主路径 |
| `protocol` / `legacy` | 兼容旧路径，不执行账号 Risk 探测，成功号为 UNCHECKED；易被 Castle deny，不推荐 |

## 注意事项

- 仅供学习与自用自动化，请遵守目标站点与服务条款。
- 仓库不包含真实 `.env`、代理账号、邮箱密码、keys/logs。
- 推送前请确认工作区无个人域名、代理凭证与内网地址。
