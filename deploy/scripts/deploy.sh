#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/compose.yaml"
DEPLOY_ENV="${DEPLOY_ENV_FILE:-$ROOT_DIR/deploy/deploy.env}"
STATE_FILE="$ROOT_DIR/deploy/.deploy-state"

force=0
target_ref=""
target_tag=""

usage() {
  echo "用法: $0 <镜像标签> [--force]" >&2
  echo "      $0 --image-ref <完整镜像引用> [--force]" >&2
  echo "示例: $0 v1.3.0" >&2
}

while (($#)); do
  case "$1" in
    --force)
      force=1
      shift
      ;;
    --image-ref)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      target_ref="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -* )
      echo "未知参数: $1" >&2
      usage
      exit 2
      ;;
    *)
      [[ -z "$target_tag" ]] || { usage; exit 2; }
      target_tag="$1"
      shift
      ;;
  esac
done

[[ -f "$DEPLOY_ENV" ]] || {
  echo "缺少部署配置: $DEPLOY_ENV（先复制 deploy/deploy.env.example）" >&2
  exit 1
}
[[ -f "$ROOT_DIR/.env" ]] || {
  echo "缺少应用配置: $ROOT_DIR/.env（先复制 .env.example 并填写真实配置）" >&2
  exit 1
}

for command in docker curl python3 awk mktemp; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "缺少命令: $command" >&2
    exit 1
  }
done

env_value() {
  local key="$1" file="$2"
  awk -v wanted="$key" '
    /^[[:space:]]*#/ { next }
    {
      line=$0
      sub(/^[[:space:]]*/, "", line)
      if (index(line, wanted "=") == 1) {
        sub(/^[^=]*=/, "", line)
        gsub(/\r$/, "", line)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        gsub(/^"|"$/, "", line)
        print line
        exit
      }
    }
  ' "$file"
}

set_env_value() {
  local key="$1" value="$2" file="$3" temp_file
  temp_file="$(mktemp "${file}.XXXXXX")"
  awk -v wanted="$key" -v replacement="$value" '
    BEGIN { done=0 }
    {
      line=$0
      trimmed=line
      sub(/^[[:space:]]*/, "", trimmed)
      if (!done && index(trimmed, wanted "=") == 1) {
        print wanted "=" replacement
        done=1
      } else {
        print line
      }
    }
    END {
      if (!done) print wanted "=" replacement
    }
  ' "$file" >"$temp_file"
  chmod 600 "$temp_file"
  mv -f "$temp_file" "$file"
}

repository="$(env_value GROK_IMAGE_REPOSITORY "$DEPLOY_ENV")"
configured_ref="$(env_value GROK_IMAGE_REF "$DEPLOY_ENV")"
host_port="$(env_value GROK_HOST_PORT "$DEPLOY_ENV")"
health_timeout="$(env_value DEPLOY_HEALTH_TIMEOUT "$DEPLOY_ENV")"

[[ -n "$repository" ]] || { echo "GROK_IMAGE_REPOSITORY 不能为空" >&2; exit 1; }
[[ "$repository" =~ ^[a-z0-9.-]+/[a-z0-9._/-]+$ ]] || {
  echo "GROK_IMAGE_REPOSITORY 格式无效或含大写字符: $repository" >&2
  exit 1
}
[[ "$host_port" =~ ^[0-9]{2,5}$ ]] || { echo "GROK_HOST_PORT 无效" >&2; exit 1; }
[[ "$health_timeout" =~ ^[0-9]+$ ]] || health_timeout=180

if [[ -n "$target_tag" ]]; then
  [[ "$target_tag" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || {
    echo "镜像标签格式无效: $target_tag" >&2
    exit 1
  }
  target_ref="${repository}:${target_tag}"
fi
[[ -n "$target_ref" ]] || { usage; exit 2; }
[[ "$target_ref" == "$repository":* || "$target_ref" == "$repository"@sha256:* ]] || {
  echo "目标镜像必须属于 $repository" >&2
  exit 1
}

compose=(docker compose --env-file "$DEPLOY_ENV" -f "$COMPOSE_FILE")

service_container_id() {
  "${compose[@]}" ps --all -q grok-web 2>/dev/null || true
}

check_idle() {
  python3 - "$host_port" <<'PY'
import json
import sys
from urllib.error import URLError
from urllib.request import urlopen

port = int(sys.argv[1])
base = f"http://127.0.0.1:{port}"

def fetch(path):
    with urlopen(base + path, timeout=5) as response:
        return json.load(response)

try:
    status = fetch("/api/status")
    jobs = fetch("/api/import-services/jobs")
except (OSError, URLError, ValueError, json.JSONDecodeError) as exc:
    print(f"无法确认当前任务是否空闲: {exc}", file=sys.stderr)
    raise SystemExit(2)

active = [
    str(job.get("id") or "?")
    for job in jobs.get("jobs", [])
    if job.get("status") in {"queued", "running", "cancelling"}
]
if status.get("running") or active:
    details = []
    if status.get("running"):
        details.append("注册任务仍在运行")
    if active:
        details.append("导入任务仍在运行: " + ", ".join(active[:10]))
    print("；".join(details), file=sys.stderr)
    raise SystemExit(1)
PY
}

wait_for_health() {
  local timeout="$1" deadline container_id status
  deadline=$((SECONDS + timeout))
  while ((SECONDS < deadline)); do
    container_id="$(service_container_id)"
    if [[ -n "$container_id" ]]; then
      status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || true)"
      case "$status" in
        healthy)
          return 0
          ;;
        exited|dead)
          return 1
          ;;
      esac
    fi
    sleep 3
  done
  return 1
}

existing_id="$(service_container_id)"
previous_ref=""
if [[ -n "$existing_id" ]]; then
  previous_ref="$configured_ref"
  inspected_ref="$(docker inspect --format '{{.Config.Image}}' "$existing_id" 2>/dev/null || true)"
  [[ -z "$inspected_ref" ]] || previous_ref="$inspected_ref"
  existing_running="$(docker inspect --format '{{.State.Running}}' "$existing_id" 2>/dev/null || true)"
  if ((force == 0)) && [[ "$existing_running" == "true" ]]; then
    echo "检查当前实例是否存在运行任务……"
    check_idle || {
      echo "部署已停止。请先排空任务；仅在明确接受中断时使用 --force。" >&2
      exit 1
    }
  fi
fi

mkdir -p \
  "$ROOT_DIR/keys" \
  "$ROOT_DIR/logs" \
  "$ROOT_DIR/register_sso" \
  "$ROOT_DIR/converted_auth" \
  "$ROOT_DIR/data"

echo "拉取镜像: $target_ref"
GROK_IMAGE_REF="$target_ref" "${compose[@]}" pull grok-web

echo "启动新版本……"
GROK_IMAGE_REF="$target_ref" "${compose[@]}" up -d --no-build --force-recreate grok-web

if wait_for_health "$health_timeout"; then
  set_env_value GROK_IMAGE_REF "$target_ref" "$DEPLOY_ENV"
  {
    printf 'CURRENT_IMAGE_REF=%s\n' "$target_ref"
    printf 'PREVIOUS_IMAGE_REF=%s\n' "$previous_ref"
  } >"$STATE_FILE"
  chmod 600 "$STATE_FILE"
  echo "部署成功且容器健康: $target_ref"
  exit 0
fi

echo "新版本未通过健康检查。最近容器日志：" >&2
GROK_IMAGE_REF="$target_ref" "${compose[@]}" logs --tail=120 grok-web >&2 || true

if [[ -n "$previous_ref" && "$previous_ref" != "$target_ref" ]]; then
  echo "自动恢复上一镜像: $previous_ref" >&2
  GROK_IMAGE_REF="$previous_ref" "${compose[@]}" up -d --no-build --force-recreate grok-web
  if wait_for_health "$health_timeout"; then
    set_env_value GROK_IMAGE_REF "$previous_ref" "$DEPLOY_ENV"
    echo "已恢复上一版本。持久化数据未做回滚。" >&2
  else
    echo "上一版本也未恢复健康，请立即人工检查。" >&2
  fi
else
  echo "没有可回滚的上一镜像，停止失败容器。" >&2
  GROK_IMAGE_REF="$target_ref" "${compose[@]}" stop grok-web || true
fi

exit 1
