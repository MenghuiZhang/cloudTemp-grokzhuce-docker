#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
RESTIC_ENV="${RESTIC_ENV_FILE:-$ROOT_DIR/deploy/restic.env}"
DEPLOY_ENV="${DEPLOY_ENV_FILE:-$ROOT_DIR/deploy/deploy.env}"

command -v restic >/dev/null 2>&1 || {
  echo "缺少 restic，请先安装。" >&2
  exit 1
}
[[ -f "$RESTIC_ENV" ]] || {
  echo "缺少备份配置: $RESTIC_ENV（先复制 deploy/restic.env.example）" >&2
  exit 1
}
[[ -f "$ROOT_DIR/.env" ]] || {
  echo "缺少应用配置: $ROOT_DIR/.env" >&2
  exit 1
}

set -a
# restic.env 是管理员创建且权限应为 600 的可信配置文件。
source "$RESTIC_ENV"
set +a

project="grok-prod"
if [[ -f "$DEPLOY_ENV" ]]; then
  configured_project="$(awk -F= '$1 == "COMPOSE_PROJECT_NAME" {sub(/^[^=]*=/, ""); print; exit}' "$DEPLOY_ENV")"
  [[ -z "$configured_project" ]] || project="$configured_project"
fi

paths=("$ROOT_DIR/.env")
for relative in keys register_sso converted_auth data; do
  [[ -e "$ROOT_DIR/$relative" ]] && paths+=("$ROOT_DIR/$relative")
done

echo "创建加密异地备份: $project"
restic backup --tag "$project" "${paths[@]}"

echo "执行保留策略: 每日 7 份、每周 4 份"
restic forget --tag "$project" --keep-daily 7 --keep-weekly 4 --prune

echo "备份完成。请按计划定期执行 restic restore 做恢复演练。"
