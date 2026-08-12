#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
DEPLOY_ENV="$ROOT_DIR/deploy/deploy.env"
APP_ENV="$ROOT_DIR/.env"
VERSION="${1:-v1.0.0}"
IMAGE_REPOSITORY="ghcr.io/menghuizhang/cloudtemp-grokzhuce-docker"
IMAGE_REF="${IMAGE_REPOSITORY}:${VERSION}"

usage() {
  echo "用法: $0 [版本标签]" >&2
  echo "示例: $0 v1.0.0" >&2
}

if [[ "$VERSION" == "-h" || "$VERSION" == "--help" ]]; then
  usage
  exit 0
fi

[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([._-][A-Za-z0-9.-]+)?$ ]] || {
  echo "正式版标签格式无效: $VERSION" >&2
  usage
  exit 2
}

for command in docker curl; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "缺少命令: $command" >&2
    exit 1
  }
done

docker compose version >/dev/null 2>&1 || {
  echo "未找到 Docker Compose v2（docker compose）。请先在 1Panel 安装 Docker。" >&2
  exit 1
}

[[ -f "$ROOT_DIR/compose.yaml" && -f "$ROOT_DIR/deploy/deploy.env.example" ]] || {
  echo "请在项目根目录中运行本脚本。" >&2
  exit 1
}

if [[ ! -f "$APP_ENV" ]]; then
  cp "$ROOT_DIR/.env.example" "$APP_ENV"
  echo "已创建应用配置: $APP_ENV"
else
  echo "保留现有应用配置: $APP_ENV"
fi

if [[ ! -f "$DEPLOY_ENV" ]]; then
  cp "$ROOT_DIR/deploy/deploy.env.example" "$DEPLOY_ENV"
  echo "已创建部署配置: $DEPLOY_ENV"
else
  echo "保留现有部署配置: $DEPLOY_ENV"
fi

chmod 600 "$APP_ENV" "$DEPLOY_ENV"
mkdir -p \
  "$ROOT_DIR/keys" \
  "$ROOT_DIR/logs" \
  "$ROOT_DIR/register_sso" \
  "$ROOT_DIR/converted_auth" \
  "$ROOT_DIR/data"

echo
echo "检查当前 Linux 用户已有的 GHCR 拉取权限……"
if docker pull "$IMAGE_REF" >/dev/null 2>&1; then
  echo "已有有效的 GHCR 登录，跳过令牌输入。"
else
  echo "未检测到可用的 GHCR 登录，需要输入只读凭据。"
  echo "令牌只需 read:packages 权限，输入时不会回显。"
  read -rp "GitHub 机器账号: " ghcr_user
  [[ -n "$ghcr_user" ]] || { echo "GitHub 账号不能为空" >&2; exit 1; }
  read -rsp "GHCR 只读令牌: " ghcr_token
  echo
  [[ -n "$ghcr_token" ]] || { echo "GHCR 令牌不能为空" >&2; exit 1; }

  if ! printf '%s' "$ghcr_token" | docker login ghcr.io -u "$ghcr_user" --password-stdin; then
    unset ghcr_token
    echo "GHCR 登录失败。请确认账号有该私有 Package 的读取权限。" >&2
    exit 1
  fi
  unset ghcr_token

  docker pull "$IMAGE_REF" >/dev/null 2>&1 || {
    echo "登录成功，但账号无权拉取 $IMAGE_REF。" >&2
    exit 1
  }
fi

echo
echo "开始部署正式版 $VERSION……"
"$SCRIPT_DIR/deploy.sh" "$VERSION"

echo
echo "安装完成："
echo "  本机健康检查: http://127.0.0.1:3333/api/health"
echo "  1Panel 代理目标: http://127.0.0.1:3333"
echo
echo "Sub2API 可以稍后在 Web 控制台的“导入服务”页面填写、保存并测试。"
echo "本项目没有安装或启动任何反向代理组件。"
