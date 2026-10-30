"""一个常驻监测进程；只有需要认证或首次显示成功时才创建临时窗口。"""

import argparse
from concurrent.futures import Future
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

from login import ROOT, inspect_network, load_config, login_once, network_signature

RUNTIME = ROOT / ".runtime"
BUILD = "2026-10-30.3"
LOGGER = logging.getLogger("campus_monitor")


class AlreadyRunning(Exception):
    pass


class FileLock:
    """OS 级锁随进程退出释放；残留文件不会阻止下次启动。"""

    def __init__(self, path):
        self.path = Path(path)
        self.file = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.file = self.path.open("a+b")
        if self.file.seek(0, 2) == 0:
            self.file.write(b"0")
            self.file.flush()
        self.file.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.file.close()
            self.file = None
            raise AlreadyRunning from None
        return self

    def __exit__(self, *args):
        if self.file:
            self.file.close()
            self.file = None


def running():
    try:
        with FileLock(RUNTIME / "monitor.lock"):
            return False
    except AlreadyRunning:
        return True


def write_status(state, message):
    RUNTIME.mkdir(exist_ok=True)
    data = {"pid": os.getpid(), "build": BUILD, "state": state, "message": message,
            "updated": time.strftime("%Y-%m-%d %H:%M:%S")}
    temporary = RUNTIME / f"status.{os.getpid()}.tmp"
    temporary.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    # Windows 上 status.bat 正在读取时，短暂的文件占用不能导致后台退出。
    for attempt in range(3):
        try:
            temporary.replace(RUNTIME / "status.json")
            break
        except PermissionError:
            if attempt < 2:
                time.sleep(0.02)
    else:
        temporary.unlink(missing_ok=True)


def read_status():
    try:
        return json.loads((RUNTIME / "status.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def configure_logging(name="monitor"):
    RUNTIME.mkdir(exist_ok=True)
    if not LOGGER.handlers:
        handler = RotatingFileHandler(RUNTIME / f"{name}.log", maxBytes=512 * 1024,
                                      backupCount=2 if name == "monitor" else 1, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        LOGGER.addHandler(handler)
        LOGGER.setLevel(logging.INFO)


class MonitorPolicy:
    """独立状态机：复查、成功去重、网络切换及失败退避，可离线验证。"""

    def __init__(self, config):
        self.config = config
        self.signature = None
        self.failures = 0
        self.attempts = 0
        self.next_attempt = 0
        self.accepted = False
        self.saw_internet = False

    def change_network(self, signature):
        if signature == self.signature:
            return False
        self.signature = signature
        self.failures = self.attempts = 0
        self.next_attempt = 0
        self.accepted = self.saw_internet = False
        return True

    def observe(self, status, now, *, network_changed=False):
        if status.state in ("online", "authenticated"):
            self.failures = self.attempts = 0
            self.accepted = True
            if status.state == "online":
                self.saw_internet = True
            return False
        if status.state != "needs_login":
            self.failures = 0
            return False
        # 服务端已接受登录，但探测站点/状态接口不可用时，不能据此每隔几秒重新认证。
        if self.accepted and not self.saw_internet and not status.explicit_offline:
            self.failures = 0
            return False
        self.failures += 1
        required = 1 if network_changed and status.explicit_offline else self.config["offline_confirmations"]
        return self.failures >= required and now >= self.next_attempt

    def attempted(self, now):
        self.attempts += 1
        self.failures = 0
        delay = min(self.config["retry_interval"] * 2 ** min(self.attempts - 1, 10),
                    self.config["max_retry_interval"])
        self.next_attempt = now + delay

    def completed(self, code, now):
        if code == 0:
            self.accepted = True
            self.saw_internet = False
            self.failures = self.attempts = 0
            self.next_attempt = now + self.config["retry_interval"]
        elif code == 2:
            self.next_attempt = now + self.config["auth_failure_interval"]


def python_executable(windowless=False):
    current = Path(sys.executable)
    candidate = current.with_name("pythonw.exe" if windowless else "python.exe")
    return str(candidate if os.name == "nt" and candidate.exists() else current)


def spawn_worker(config_path, ip, notice=False, portal=None):
    command = [python_executable(), "-B", "-u", str(ROOT / "login.py"),
               "--config", str(config_path), "--worker", "--expected-ip", ip]
    if notice:
        command.extend(["--notice", notice])
    if portal:
        command.extend(["--portal-host", portal["portal_host"], "--ac-id", portal["ac_id"]])
    options = {"creationflags": subprocess.CREATE_NEW_CONSOLE} if os.name == "nt" else {}
    return subprocess.Popen(command, cwd=ROOT, **options)


def run_worker(config, expected_ip=None, notice=False):
    if os.name == "nt":
        import ctypes
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        ctypes.windll.kernel32.SetConsoleTitleW("校园网自动连接")
    # 临时任务使用独立日志，避免两个 Windows 进程同时轮转同一个文件。
    configure_logging("login")
    try:
        with FileLock(RUNTIME / "login.lock"):
            if notice:
                message = ("校园网认证仍有效，无需重复登录。"
                           if notice == "authenticated" else
                           "连接成功，当前已可上网，无需重复登录。")
                print("[OK] " + message, flush=True)
                code = 0
            else:
                print("[*] 检测到校园网连接需要恢复，正在检查并自动重连……", flush=True)
                result = login_once(config, expected_ip)
                code = result.code
                print(("[OK] " if code == 0 else "[!] ") + result.message, flush=True)
                LOGGER.info("认证结果 code=%s %s", code, result.message)
            seconds = config["success_display_seconds"] if code == 0 else config["failure_display_seconds"]
            print(f"[*] {seconds:g} 秒后关闭此窗口，后台继续监测。", flush=True)
            time.sleep(seconds)
            return code
    except AlreadyRunning:
        print("[*] 已有认证任务正在运行，无需重复执行。", flush=True)
        return 3


def submit_check(config, *, quick=False):
    """网络 I/O 放在至多两个后台线程中，不阻塞主循环发现网卡切换。"""
    future = Future()

    def run():
        try:
            future.set_result(inspect_network(config, quick=quick))
        except Exception as error:
            future.set_exception(error)

    threading.Thread(target=run, name="campus-quick" if quick else "campus-check", daemon=True).start()
    return future


def monitor(config_path, *, max_ticks=None):
    """网络变化走快速通道；普通外网检测不会阻塞网络切换处理。"""
    configure_logging()
    worker = None
    worker_signature = None
    worker_is_notice = False
    try:
        with FileLock(RUNTIME / "monitor.lock"):
            stop_file = RUNTIME / "stop.request"
            stop_file.unlink(missing_ok=True)
            config = load_config(config_path)
            config_stamp = config_path.stat().st_mtime_ns
            policy = MonitorPolicy(config)
            write_status("starting", "后台监测已启动，正在等待网络稳定")
            LOGGER.info("后台监测启动 build=%s", BUILD)
            last_message = None
            next_check = 0
            initial_notice = True
            route_pending = True
            generation = 0
            portal_context = {}
            # 快速检测和普通检测各至多一个，不会因 DNS 卡住而不断创建线程。
            pending = {"quick": None, "regular": None}
            ticks = 0
            try:
                while not stop_file.exists() and (max_ticks is None or ticks < max_ticks):
                    ticks += 1
                    now = time.monotonic()
                    if worker and worker.poll() is not None:
                        if worker_signature == policy.signature and not worker_is_notice:
                            policy.completed(worker.returncode, now)
                            if worker.returncode == 0:
                                write_status("authenticated", "校园网登录任务成功，后台继续监测")
                            elif worker.returncode == 2:
                                write_status("auth_rejected", "认证被拒绝，请检查配置；稍后再试")
                        LOGGER.info("临时窗口结束 code=%s", worker.returncode)
                        worker = None
                    try:
                        stamp = config_path.stat().st_mtime_ns
                        if stamp != config_stamp:
                            config = load_config(config_path)
                            config_stamp = stamp
                            policy = MonitorPolicy(config)
                            next_check = 0
                            LOGGER.info("已重新加载配置")
                    except (OSError, ValueError):
                        write_status("config_error", "新配置无效，继续使用之前的配置，请检查配置文件")
                    signature = network_signature(config)
                    if policy.change_network(signature):
                        generation += 1
                        portal_context = {}
                        route_pending = True
                        next_check = now + config["network_settle_seconds"]
                        write_status("settling", "网络发生变化，正在快速检查校园网")
                        LOGGER.info("网络路径变化，启动快速检测")
                        if worker and worker_signature != signature and worker.poll() is None:
                            worker.terminate()
                            try:
                                worker.wait(timeout=1)
                            except subprocess.TimeoutExpired:
                                worker.kill()
                                worker.wait()
                            worker = None
                            LOGGER.info("网络已切换，取消旧网络的临时任务")
                    for kind in ("quick", "regular"):
                        record = pending[kind]
                        if record is None or not record[0].done():
                            continue
                        pending[kind] = None
                        future, checked_signature, checked_generation, started, changed = record
                        if checked_signature != signature or checked_generation != generation:
                            continue
                        try:
                            status = future.result()
                        except Exception as error:
                            LOGGER.warning("网络检测异常=%s", type(error).__name__)
                            status = None
                        if kind == "quick":
                            route_pending = False
                        if status is None:
                            next_check = now + config["check_interval"]
                            continue
                        if status.portal_host and status.ac_id:
                            detected = {"portal_host": status.portal_host, "ac_id": status.ac_id}
                            if detected != portal_context:
                                LOGGER.info("当前认证入口 host=%s ac_id=%s", status.portal_host, status.ac_id)
                            portal_context = detected
                        message_key = (status.state, status.message)
                        if message_key != last_message:
                            LOGGER.info("状态 %s：%s（检测耗时 %.2fs）", status.state, status.message, now - started)
                            last_message = message_key
                        write_status(status.state, status.message)
                        should_login = policy.observe(status, now, network_changed=changed)
                        if worker is None and (should_login or (initial_notice and status.state in ("online", "authenticated"))):
                            worker_is_notice = not should_login
                            worker = spawn_worker(config_path, status.ip,
                                                  notice=status.state if worker_is_notice else False,
                                                  portal=portal_context)
                            worker_signature = signature
                            if should_login:
                                policy.attempted(now)
                                LOGGER.info("已确认需要认证，打开重连窗口")
                            initial_notice = False
                        elif status.state == "needs_login":
                            initial_notice = False
                        # 快速检查未确认校园网时，异步查询外网状态，不打扰热点连接。
                        next_check = (now if kind == "quick" and status.state in ("unknown", "waiting")
                                      and pending["regular"] is None else now + config["check_interval"])
                    if now >= next_check and worker is None:
                        kind = "quick" if route_pending else "regular"
                        # 旧网络的 DNS 请求仍挂起时，当前校园网仍可继续做数字地址检查。
                        if kind == "regular" and pending[kind] is not None and pending["quick"] is None:
                            kind = "quick"
                        if pending[kind] is None:
                            future = submit_check({**config, **portal_context,
                                                   "_portal_verified": bool(portal_context)}, quick=(kind == "quick"))
                            pending[kind] = (future, signature, generation, now, route_pending)
                            next_check = now + config["check_interval"]
                    time.sleep(config["route_check_interval"])
            except KeyboardInterrupt:
                pass
            finally:
                if worker and worker.poll() is None:
                    worker.terminate()
                    try:
                        worker.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        worker.kill()
                        worker.wait()
                stop_file.unlink(missing_ok=True)
                write_status("stopped", "后台监测已停止")
                LOGGER.info("后台监测停止")
            return 0
    except AlreadyRunning:
        return 0


def manage(action, config_path):
    config_path = Path(config_path).resolve()
    if action == "status":
        active = running()
        print("[OK] 后台监测正在运行。" if active else "[*] 后台监测未运行。")
        status = read_status()
        if status:
            print(f"最近状态：{status.get('message', '')}（{status.get('updated', '')}）")
            print(f"程序版本：{status.get('build', '旧版')}，进程：{status.get('pid', '?')}")
        print(f"日志位置：{RUNTIME / 'monitor.log'}")
        return 0
    if action == "stop":
        if not running():
            print("[*] 后台监测未运行。")
            return 0
        (RUNTIME / "stop.request").touch()
        deadline = time.monotonic() + 20
        while running() and time.monotonic() < deadline:
            time.sleep(0.2)
        if running():
            print("[*] 停止请求已发出，正在等待当前网络请求结束。")
        else:
            print("[OK] 后台监测已停止。")
        return 0
    if action == "foreground":
        print("[*] 前台监测：正常联网时只检测、不重复登录。按 Ctrl+C 退出。", flush=True)
        return monitor(config_path)
    if running():
        print("[OK] 后台监测已经在运行；以后切换网络无需再点击 start.bat。")
        return 0
    RUNTIME.mkdir(exist_ok=True)
    command = [python_executable(windowless=True), "-B", str(ROOT / "monitor.py"),
               "--config", str(config_path)]
    options = {}
    if os.name == "nt":
        options["creationflags"] = subprocess.CREATE_NO_WINDOW
    with open(os.devnull, "wb") as sink:
        process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                   stdout=sink, stderr=sink, **options)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if running() and read_status().get("pid") == process.pid:
            print("[OK] 后台监测已启动；正常联网时不会重复登录。")
            print("[*] 只需启动一次；关闭此窗口后继续监测，切换网线/Wi-Fi 无需再点启动。")
            return 0
        if process.poll() is not None:
            if running():
                print("[OK] 后台监测已经在运行。")
                return 0
            break
        time.sleep(0.1)
    print(f"[!] 后台启动尚未确认，请运行 status.bat 查看状态；日志：{RUNTIME / 'monitor.log'}")
    return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=ROOT / "config.json")
    args = parser.parse_args()
    try:
        sys.exit(monitor(args.config.resolve()))
    except Exception as error:
        configure_logging()
        # 不记录异常正文，requests 异常中可能带有认证 URL。
        LOGGER.error("监测意外退出（%s），请检查配置和文件权限", type(error).__name__)
        sys.exit(1)
