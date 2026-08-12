#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
STATE_FILE="$ROOT_DIR/deploy/.deploy-state"

[[ -f "$STATE_FILE" ]] || {
  echo "没有部署状态文件，无法确定上一镜像。" >&2
  exit 1
}

previous_ref="$(awk -F= '$1 == "PREVIOUS_IMAGE_REF" {sub(/^[^=]*=/, ""); print; exit}' "$STATE_FILE")"
[[ -n "$previous_ref" ]] || {
  echo "部署状态中没有上一镜像。" >&2
  exit 1
}

exec "$SCRIPT_DIR/deploy.sh" --image-ref "$previous_ref" "$@"
