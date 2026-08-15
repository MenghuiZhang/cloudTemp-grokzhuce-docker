# Docker 生产部署

本目录用于在一台 Linux 服务器同时运行正式版和测试版。两个实例使用不同的
Compose 项目名、回环端口、应用配置和持久化目录，因此会分别创建
`grok-prod_private` 与 `grok-test_private` 网络。网络不要设置 `internal: true`：
注册、邮箱、代理和 Sub2API 都需要容器访问外网。

## 1. GHCR 发布规则

`.github/workflows/publish-image.yml` 会先执行单元测试，再构建
`linux/amd64` 和 `linux/arm64`：

- 推送 `main`：发布 `main` 与 `sha-<commit>` 标签，供测试环境使用。
- 推送 `vX.Y.Z` 标签：发布精确版本标签，供正式环境使用。
- Pull Request：只运行测试，不发布镜像。
- 不生成 `latest`，避免正式环境隐式漂移。

首次发布的 GHCR Package 默认为私有。请在 Package 设置中确认它已关联本仓库，
并给专用机器账号授予读取权限。服务器使用该账号的 classic PAT，权限仅需
`read:packages`：

```bash
export GHCR_USER='REPLACE_WITH_MACHINE_ACCOUNT'
read -rsp 'GHCR token: ' GHCR_TOKEN
printf '%s' "$GHCR_TOKEN" | docker login ghcr.io -u "$GHCR_USER" --password-stdin
unset GHCR_TOKEN
```

工作流推送使用仓库自带的 `GITHUB_TOKEN`，不需要把 PAT 保存到 Actions Secrets。
官方参考：[GitHub Container registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)、
[使用 Actions 发布 Docker 镜像](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images)。

## 2. 准备正式与测试目录

把仓库分别放到两个目录，避免 `.env`、keys 和任务结果互相污染：

```text
/opt/grok/prod
/opt/grok/test
```

在每个目录中准备文件：

```bash
cp .env.example .env
cp deploy/deploy.env.example deploy/deploy.env
mkdir -p keys logs register_sso converted_auth data
chmod 600 .env deploy/deploy.env
```

正式环境 `deploy/deploy.env` 示例值：

```dotenv
COMPOSE_PROJECT_NAME=grok-prod
GROK_BIND_ADDRESS=127.0.0.1
GROK_HOST_PORT=3333
GROK_IMAGE_REPOSITORY=ghcr.io/menghuizhang/cloudtemp-grokzhuce-docker
GROK_IMAGE_REF=ghcr.io/menghuizhang/cloudtemp-grokzhuce-docker:v1.2.0
DEPLOY_HEALTH_TIMEOUT=180
```

测试环境改为：

```dotenv
COMPOSE_PROJECT_NAME=grok-test
GROK_HOST_PORT=3334
GROK_IMAGE_REF=ghcr.io/menghuizhang/cloudtemp-grokzhuce-docker:main
```

根目录 `.env` 只保存应用配置和秘密。应用网页会重写该文件，因此不要把
Compose 参数放进去。Docker 中的 `UI_PORT` 必须保持 `3333`；宿主机端口由
`deploy/deploy.env` 映射。

如果 Sub2API 已有 HTTPS 反代，请让以下两项使用同一个根地址，不要写容器内的
`127.0.0.1:9898`：

```dotenv
SUB2API_URL=https://SUB2API_DOMAIN.example.com
UPSTREAM_URL=https://SUB2API_DOMAIN.example.com
```

`UPSTREAM_URL` 只是旧版兼容变量，新配置以 `SUB2API_URL` 为准。

## 3. 首次启动与更新

只安装一个正式实例时，可在完成 GHCR 机器账号授权后运行：

```bash
./deploy/scripts/install-prod.sh v1.2.0
```

脚本会创建缺失的 `.env`、`deploy/deploy.env` 和持久化目录，先复用当前 Linux
用户已有的 GHCR 登录；没有拉取权限时才提示输入只读凭据，然后部署一个正式容器。
它不会安装或启动任何反代组件。已有配置文件会原样保留，不会覆盖。首次安装后仍需
进入 Web 控制台配置邮箱等实际服务。

脚本会拉取选定镜像、重建单个服务并等待 Docker 健康检查。更新前会检查注册任务
以及导入任务；任一任务运行时拒绝更新。成功后会把精确镜像引用写回
`deploy/deploy.env`，失败则自动恢复上一镜像。

```bash
# 正式环境：只部署已经由 CI 发布的版本标签
./deploy/scripts/deploy.sh v1.2.0

# 测试环境
./deploy/scripts/deploy.sh main

# 查看状态与独立网络
docker compose --env-file deploy/deploy.env ps
docker network ls --filter name=grok-
```

仅在已经接受任务中断时才可使用 `--force`。它不会安全保存内存中的任务状态：

```bash
./deploy/scripts/deploy.sh v1.2.0 --force
```

手动切回部署状态中记录的上一镜像：

```bash
./deploy/scripts/rollback.sh
```

镜像回滚不会回滚 `.env`、keys、注册结果或其他持久化数据。正式更新前应先完成
一次可验证的异地备份。

## 4. 接入现有 1Panel 反向代理

本项目不包含、安装或启动 Nginx、Caddy、Fail2ban 等反代组件。应用端口只监听
宿主机回环地址，请在现有 1Panel 网站中分别配置：

```text
正式域名 → http://127.0.0.1:3333
测试域名 → http://127.0.0.1:3334
```

在 1Panel 中启用 HTTPS，并为两个站点设置独立的访问认证和登录限速。普通请求超时
可保持 60 秒；Solver、代理测试和导入类接口可能执行较久，建议把相关站点的代理
超时设为约 300 秒。具体证书、认证和安全策略均由现有 1Panel 管理。

## 5. 日志与备份

Compose 已限制每个容器的 JSON 日志为 `10 MB × 5`。应用文件日志使用
`deploy/logrotate/grok-prod.example`，替换其中的部署用户后安装到
`/etc/logrotate.d/grok-prod`，每日轮转并保留约 14 天。

生产备份使用 restic 加密后发送到另一台服务器或对象存储：

```bash
cp deploy/restic.env.example deploy/restic.env
chmod 600 deploy/restic.env
# RESTIC_PASSWORD_FILE 指向的文件也必须 chmod 600，并另行安全保管密码。
set -a; source deploy/restic.env; set +a
restic init
./deploy/scripts/backup.sh
```

脚本只备份 `.env`、`keys/`、`register_sso/`、`converted_auth/` 和 `data/`，不备份
应用日志；保留每日 7 份、每周 4 份。可按
`deploy/systemd/grok-backup.*.example` 安装每日 timer。测试环境默认不启用备份。

至少每月执行一次恢复演练，例如恢复到临时目录并核对文件，而不是只看备份任务成功：

```bash
restic snapshots --tag grok-prod
restic restore latest --tag grok-prod --target /tmp/grok-restore-test
```

restic 的仓库类型、凭据环境变量和恢复选项以
[官方备份文档](https://restic.readthedocs.io/en/stable/040_backup.html) 为准。

## 6. 上线检查

- `docker compose --env-file deploy/deploy.env config` 能成功解析。
- `docker compose --env-file deploy/deploy.env ps` 显示容器为 `healthy`。
- `ss -lnt` 只显示 `127.0.0.1:3333` / `127.0.0.1:3334`，没有 `0.0.0.0`。
- 正式和测试实例位于不同的 `*_private` 网络。
- 两个域名均已在 1Panel 中启用 HTTPS，并要求各自的访问认证。
- 1Panel 已设置访问限速，Docker 与应用日志不会无限增长。
- Sub2API 连通测试通过，地址为 HTTPS 反代域名。
- 备份在异地仓库可见，恢复演练成功。
