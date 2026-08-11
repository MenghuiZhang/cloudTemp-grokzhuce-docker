#!/usr/bin/env python3
"""项目一键启动器。

首次运行会创建 .venv 并安装 requirements.txt，后续直接复用该环境。
默认启动本地 Solver 和 Web 控制台 app.py；本地 Solver 的浏览器依赖按需显式安装。
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
VENV_DIR = BASE_DIR / ".venv"
REQUIREMENTS = BASE_DIR / "requirements.txt"
INSTALL_MARKER = VENV_DIR / ".requirements.sha256"
MIN_PYTHON = (3, 10)


def venv_python() -> Path:
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def in_project_venv() -> bool:
    try:
        return Path(sys.prefix).resolve() == VENV_DIR.resolve()
    except OSError:
        return False


def requirements_digest() -> str:
    return hashlib.sha256(REQUIREMENTS.read_bytes()).hexdigest()


def run(command: list[str], *, env: dict[str, str] | None = None) -> int:
    print("\n>", " ".join(command), flush=True)
    try:
        return subprocess.call(command, cwd=BASE_DIR, env=env)
    except KeyboardInterrupt:
        return 130


def ensure_supported_python() -> None:
    if sys.version_info < MIN_PYTHON:
        version = ".".join(map(str, MIN_PYTHON))
        raise SystemExit(f"[错误] 需要 Python {version} 或更高版本，当前为 {sys.version.split()[0]}")


def ensure_venv() -> None:
    python = venv_python()
    if python.exists():
        return

    print(f"[首次运行] 正在创建虚拟环境：{VENV_DIR}", flush=True)
    code = run([sys.executable, "-m", "venv", str(VENV_DIR)])
    if code != 0 or not python.exists():
        raise SystemExit("[错误] 虚拟环境创建失败，请确认当前 Python 包含 venv 模块。")


def relaunch_in_venv(args: list[str]) -> int:
    python = venv_python()
    env = os.environ.copy()
    env["VIRTUAL_ENV"] = str(VENV_DIR)
    env["PATH"] = str(python.parent) + os.pathsep + env.get("PATH", "")
    return run([str(python), str(Path(__file__).resolve()), *args], env=env)


def install_requirements(force: bool = False) -> None:
    if not REQUIREMENTS.exists():
        raise SystemExit(f"[错误] 未找到依赖文件：{REQUIREMENTS}")

    digest = requirements_digest()
    installed_digest = ""
    if INSTALL_MARKER.exists():
        installed_digest = INSTALL_MARKER.read_text(encoding="utf-8").strip()

    if not force and installed_digest == digest:
        print("[环境] Python 依赖已就绪。", flush=True)
        return

    print("[环境] 正在安装项目依赖，请稍候……", flush=True)
    code = run(
        [sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS)]
    )
    if code != 0:
        raise SystemExit("[错误] 依赖安装失败，请检查网络或 pip 输出。")
    INSTALL_MARKER.write_text(digest + "\n", encoding="utf-8")


def ensure_env_file() -> None:
    env_file = BASE_DIR / ".env"
    example = BASE_DIR / ".env.example"
    if env_file.exists() or not example.exists():
        return
    shutil.copyfile(example, env_file)
    print("[配置] 已从 .env.example 创建 .env，请在网页配置页填写实际参数。", flush=True)


def uses_local_solver() -> bool:
    """未配置第三方 YesCaptcha 时使用项目内置 Solver。"""
    from dotenv import load_dotenv

    load_dotenv(BASE_DIR / ".env", override=True)
    return not (os.getenv("YESCAPTCHA_KEY") or "").strip()


def start_local_solver(timeout: float = 120.0) -> tuple[bool, bool]:
    """确保本地 Solver 就绪，返回 (是否成功, 是否由本启动器新拉起)。"""
    try:
        import solver_manager

        before = solver_manager.status(force=True)
        result = solver_manager.ensure_ready(timeout=timeout)
    except Exception as exc:
        print(f"[错误] 本地 Solver 启动异常：{exc}", flush=True)
        return False, False
    owned = bool(
        result.get("started")
        and not before.get("process_running")
        and result.get("pid")
    )
    message = result.get("message") or "未知状态"
    if result.get("ok") and result.get("ready"):
        print(f"[Solver] {message}", flush=True)
        return True, owned

    print(f"[错误] 本地 Solver 启动失败：{message}", flush=True)
    print(
        f"[提示] 请查看 {BASE_DIR / 'logs' / 'turnstile_solver.log'}；"
        "首次使用可运行 python start.py --setup-solver。",
        flush=True,
    )
    # 只清理由本次调用创建、但未能就绪的进程。
    if owned:
        solver_manager.stop()
    return False, False


def stop_owned_solver(owned: bool) -> None:
    """Web 退出时，仅停止本启动器创建的 Solver。"""
    if not owned:
        return
    import solver_manager

    result = solver_manager.stop()
    message = result.get("message") or "Solver 已停止"
    print(f"\n[Solver] {message}", flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="自动创建/复用 .venv 并启动 Grok Web 控制台"
    )
    parser.add_argument(
        "--reinstall",
        action="store_true",
        help="强制重新安装 requirements.txt 中的依赖",
    )
    parser.add_argument(
        "--setup-solver",
        action="store_true",
        help="启动前安装 Camoufox/Chromium 等本地 Solver 浏览器（下载量较大）",
    )
    parser.add_argument(
        "--no-start",
        action="store_true",
        help="只准备虚拟环境和依赖，不启动 app.py",
    )
    parser.add_argument(
        "--no-solver",
        action="store_true",
        help="启动 Web 时跳过预启动本地 Solver",
    )
    parser.add_argument(
        "--solver-timeout",
        type=float,
        default=120.0,
        metavar="SECONDS",
        help="等待本地 Solver 就绪的秒数（默认 120）",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ensure_supported_python()

    if not in_project_venv():
        ensure_venv()
        return relaunch_in_venv(sys.argv[1:])

    install_requirements(force=args.reinstall)
    ensure_env_file()

    if args.setup_solver:
        code = run([sys.executable, str(BASE_DIR / "setup_solver.py")])
        if code != 0:
            return code

    if args.no_start:
        print(f"\n[完成] 虚拟环境已准备好：{VENV_DIR}")
        return 0

    solver_owned = False
    if not args.no_solver and uses_local_solver():
        timeout = max(5.0, float(args.solver_timeout))
        print("\n[启动] 正在检查本地 Turnstile Solver……", flush=True)
        solver_ok, solver_owned = start_local_solver(timeout=timeout)
        if not solver_ok:
            return 1
    elif args.no_solver:
        print("\n[Solver] 已通过 --no-solver 跳过预启动。", flush=True)
    else:
        print("\n[Solver] 检测到 YESCAPTCHA_KEY，跳过本地 Solver。", flush=True)

    print("\n[启动] Web 控制台：http://127.0.0.1:3333")
    print("[提示] 按 Ctrl+C 停止服务。", flush=True)
    try:
        return run([sys.executable, str(BASE_DIR / "app.py")])
    finally:
        stop_owned_solver(solver_owned)


if __name__ == "__main__":
    raise SystemExit(main())
