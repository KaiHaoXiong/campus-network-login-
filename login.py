"""校园网状态检测及一次性认证。后台监测入口见 monitor.py。"""

import argparse
import base64
import binascii
import ipaddress
import json
import logging
import re
import socket
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import requests

from srun_encrypt import get_md5, make_checksum, make_encrypted_info
from portal import (cached_entries, portal_client_ip, portal_from_response, portal_from_url,
                    portal_target, remember_portal, trusted_host)

ROOT = Path(__file__).resolve().parent
LOGGER = logging.getLogger("campus_monitor")
DEFAULTS = {
    "domain": "@cmcc", "ac_id": "8", "enc_ver": "srun_bx1",
    "n": "200", "type": "1", "portal_host": "10.110.74.99",
    "os": "Windows 10", "name": "Windows", "encryption_mode": "legacy",
    "check_interval": 10, "route_check_interval": 1, "network_settle_seconds": 0.8,
    "offline_confirmations": 2, "request_timeout": 3,
    "fast_request_timeout": 1.2, "login_timeout": 10,
    "portal_mode": "auto",
    "retry_interval": 30, "max_retry_interval": 300,
    "auth_failure_interval": 300, "success_display_seconds": 5,
    "failure_display_seconds": 15,
    "connectivity_checks": [
        {"url": "http://www.msftconnecttest.com/connecttest.txt",
         "status": 200, "body": "Microsoft Connect Test"},
        {"url": "http://connectivitycheck.platform.hicloud.com/generate_204",
         "status": 204},
    ],
}


def load_config(path=ROOT / "config.json"):
    """旧配置默认为 Base64，新模板显式使用 plain；绝不改写密码文件。"""
    with open(path, encoding="utf-8-sig") as file:
        supplied = json.load(file)
    if not isinstance(supplied, dict):
        raise ValueError("配置必须是 JSON 对象")
    config = {**DEFAULTS, **supplied}
    for field in ("username", "password"):
        if not isinstance(config.get(field), str) or not config[field]:
            raise ValueError(f"配置缺少有效的 {field}")
    encoding = config.get("password_encoding", "base64")
    if encoding == "base64":
        try:
            config["password"] = base64.b64decode(
                config["password"], validate=True).decode("utf-8")
        except (ValueError, binascii.Error, UnicodeDecodeError):
            raise ValueError("密码不是有效 Base64；若填写明文，请设置 password_encoding 为 plain") from None
    elif encoding != "plain":
        raise ValueError("password_encoding 只能为 plain 或 base64")
    if not config["password"]:
        raise ValueError("密码不能为空")
    for field in ("domain", "ac_id", "enc_ver", "n", "type", "os", "name"):
        config[field] = str(config[field])
    try:
        ipaddress.IPv4Address(config["portal_host"])
    except (ValueError, TypeError):
        raise ValueError("portal_host 应填写校园网认证服务器的 IPv4 地址") from None
    if config["encryption_mode"] not in ("legacy", "portal_js"):
        raise ValueError("encryption_mode 只能为 legacy 或 portal_js")
    if config["portal_mode"] not in ("auto", "fixed"):
        raise ValueError("portal_mode 只能为 auto 或 fixed")
    if "portal_networks" in config:
        try:
            if not isinstance(config["portal_networks"], list) or not config["portal_networks"]:
                raise ValueError
            for network in config["portal_networks"]:
                ipaddress.IPv4Network(network)
        except (ValueError, TypeError):
            raise ValueError("portal_networks 必须是允许自动识别认证入口的 IPv4 网段列表") from None
    for field in (
        "check_interval", "route_check_interval", "network_settle_seconds",
        "offline_confirmations", "request_timeout", "retry_interval",
        "max_retry_interval", "auth_failure_interval", "success_display_seconds",
        "failure_display_seconds",
        "fast_request_timeout", "login_timeout",
    ):
        value = config[field]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 86400:
            raise ValueError(f"{field} 必须是大于 0、不超过 86400 的数字")
    if int(config["offline_confirmations"]) != config["offline_confirmations"]:
        raise ValueError("offline_confirmations 必须是整数")
    checks = config["connectivity_checks"]
    if not isinstance(checks, list) or not checks:
        raise ValueError("connectivity_checks 不能为空")
    for check in checks:
        if (not isinstance(check, dict) or
                not str(check.get("url", "")).startswith(("http://", "https://")) or
                check.get("status") not in (200, 204) or
                (check["status"] == 200 and
                 (not isinstance(check.get("body"), str) or not check["body"].strip()))):
            raise ValueError("联网检测须指定网址、状态码；200 响应还须指定完整 body")
    return config


def _parse_jsonp(text):
    """兼容 JSON、JSONP；仅接受对象，防止 HTML/列表被误认成状态。"""
    text = text.strip().lstrip("\ufeff")
    if not text.startswith("{"):
        match = re.fullmatch(r"[\w.$]+\s*\((.*)\)\s*;?", text, re.DOTALL)
        if not match:
            return None
        text = match.group(1)
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def new_session():
    session = requests.Session()
    session.trust_env = False
    return session


def route_ip(host):
    """UDP connect 只向系统查询出站地址，不发送数据包。"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((host, 80))
            address = sock.getsockname()[0]
        ip = ipaddress.IPv4Address(address)
        return address if not ip.is_loopback and not ip.is_unspecified and not ip.is_link_local else ""
    except (OSError, ValueError):
        return ""


def get_local_ip(config):
    return route_ip(config["portal_host"])


def network_signature(config):
    """同时观察认证服务器路径和默认外网路径；网线/Wi-Fi 切换后重新检查。"""
    return get_local_ip(config), route_ip("1.1.1.1")


def _get(session, config, url, *, stage=None, timeout=None, **kwargs):
    started = time.monotonic()
    try:
        response = session.get(url, timeout=timeout or config["request_timeout"],
                               allow_redirects=False, **kwargs)
        if stage:
            LOGGER.info("认证阶段=%s host=%s ac_id=%s HTTP=%s 耗时=%.2fs", stage,
                        config["portal_host"], config["ac_id"], response.status_code,
                        time.monotonic() - started)
        response.raise_for_status()
        return response
    except requests.RequestException as error:
        if stage:
            LOGGER.warning("认证阶段=%s host=%s ac_id=%s 异常=%s 耗时=%.2fs", stage,
                           config["portal_host"], config["ac_id"], type(error).__name__,
                           time.monotonic() - started)
        raise


def internet_available(config, session):
    for check in config["connectivity_checks"]:
        try:
            response = _get(session, config, check["url"])
            context = portal_from_response(response, check["url"], config)
            if context:
                session._detected_portal = context
                return False
            if (response.status_code == check["status"] and
                    (check["status"] == 204 or response.text.strip() == check["body"].strip())):
                return True
        except requests.RequestException:
            continue
    return False


def portal_status(config, session, timeout=None):
    try:
        response = _get(session, config,
                        f"http://{config['portal_host']}/cgi-bin/rad_user_info",
                        params={"callback": "jsonp"}, timeout=timeout)
        data = _parse_jsonp(response.text)
        if data is None and response.text.strip().lower() in ("not_online", "not online"):
            data = {"error": "not_online"}
        return data
    except requests.RequestException:
        return None


def is_online(config):
    with new_session() as session:
        data = portal_status(config, session)
        return bool(data and data.get("error") == "ok"), data


def get_token(config, username, ip, session=None, *, timeout=None, stage=None):
    if session is None:
        with new_session() as own_session:
            return get_token(config, username, ip, own_session, timeout=timeout, stage=stage)
    response = _get(session, config,
                    f"http://{config['portal_host']}/cgi-bin/get_challenge",
                    params={"callback": "jsonp", "username": username, "ip": ip},
                    timeout=timeout, stage=stage)
    data = _parse_jsonp(response.text)
    if not data or not isinstance(data.get("challenge"), str) or not data["challenge"]:
        raise RuntimeError("认证服务器未返回有效挑战码")
    client_ip = data.get("client_ip") or ip
    try:
        ipaddress.IPv4Address(client_ip)
    except (ValueError, TypeError):
        raise RuntimeError("认证服务器未返回有效客户端 IP") from None
    return data["challenge"], client_ip


@dataclass(frozen=True)
class NetworkStatus:
    state: str
    ip: str = ""
    message: str = ""
    explicit_offline: bool = False
    portal_host: str = ""
    ac_id: str = ""
    client_ip: str = ""


OFFLINE_ERRORS = {"not_online", "not_online_error", "ip_not_online", "no_user", "user_not_online"}


def discover_portal(config, session):
    if config.get("_portal_verified") or config.get("portal_mode") == "fixed":
        return {**config, "_portal_verified": True}
    entries = cached_entries(config)
    local_ip = get_local_ip(config)
    # 精确地址缓存只加快查找，仍重新读取当前页面，不直接沿用历史认证状态。
    cached_urls = [entry["url"] for entry in entries if entry["source_ip"] == local_ip]
    hosts = list(dict.fromkeys([config["portal_host"]] + [
        portal_from_url(entry["url"], config)["portal_host"] for entry in entries]))
    urls = cached_urls + [f"http://{host}/v1/srun_portal_detect" for host in hosts]
    urls += [f"http://{host}/" for host in hosts] + ["http://1.1.1.1/"]
    for first_url in dict.fromkeys(urls):
        url = first_url
        seen = set()
        for _ in range(4):
            if url in seen:
                break
            seen.add(url)
            started = time.monotonic()
            try:
                response = _get(session, config, url, timeout=config["fast_request_timeout"])
            except requests.RequestException as error:
                LOGGER.info("入口探测未响应 host=%s 异常=%s 耗时=%.2fs",
                            url.split('/')[2], type(error).__name__, time.monotonic() - started)
                break
            # 此接口及 Pc/Redirect 字段来自实际保存的 Portal.js 的 acDetect 方法。
            if url.endswith("/v1/srun_portal_detect"):
                data = _parse_jsonp(response.text)
                if data and data.get("Redirect") and isinstance(data.get("Pc"), str):
                    from urllib.parse import urljoin
                    target = urljoin(url, data["Pc"])
                    context = portal_from_url(target, config)
                    if context:
                        LOGGER.info("AC 接口确认入口 host=%s ac_id=%s", context["portal_host"], context["ac_id"])
                        return {**config, **context, "_portal_verified": True}
                break
            target = portal_target(response, url, config)
            if not target:
                LOGGER.info("入口页面未提供有效跳转 host=%s HTTP=%s", url.split('/')[2], response.status_code)
                break
            target_url, context = target
            client_ip = portal_client_ip(response.text)
            if target_url == url and client_ip:
                remember_portal(config, local_ip, url)
                LOGGER.info("页面确认入口 host=%s ac_id=%s", context["portal_host"], context["ac_id"])
                return {**config, **context, "_portal_verified": True,
                        "_portal_client_ip": client_ip, "_captive_redirect": first_url == "http://1.1.1.1/"}
            url = target_url
    return {**config, "_portal_verified": False}


def inspect_network(config, *, quick=False):
    ip = get_local_ip(config)
    if not ip:
        return NetworkStatus("waiting", message="等待网络连接")
    with new_session() as session:
        if not quick and internet_available(config, session):
            return NetworkStatus("online", ip, "连接成功，当前已可上网，无需重复登录")
        context = session.__dict__.get("_detected_portal")
        if context:
            config = {**config, **context, "_portal_verified": True}
        else:
            config = discover_portal(config, session)
        timeout = config["fast_request_timeout"] if quick else None
        data = portal_status(config, session, timeout=timeout)
        portal = ({"portal_host": config["portal_host"], "ac_id": config["ac_id"]}
                  if config.get("_portal_verified") else {})
        if data and data.get("error") == "ok":
            return NetworkStatus("authenticated", ip, "校园网认证仍有效，保留当前连接", **portal)
        if not config.get("_portal_verified"):
            return NetworkStatus("unknown", ip, "未确认当前认证入口，已跳过旧入口登录，请查看日志")
        # 认证服务器返回挑战码，才将当前网络识别为校园网。
        try:
            get_token(config, config["username"] + config["domain"], ip, session, timeout=timeout)
        except (requests.RequestException, RuntimeError):
            return NetworkStatus("unknown", ip, "未确认校园网，或认证服务器暂不可达，等待网络恢复")
        explicit = bool(config.get("_captive_redirect") or
                        (data and str(data.get("error", "")).lower() in OFFLINE_ERRORS))
        return NetworkStatus("needs_login", ip, "校园网可达，需要检查认证", explicit,
                             **portal, client_ip=config.get("_portal_client_ip", ""))


@dataclass(frozen=True)
class LoginResult:
    code: int
    message: str


def login_once(config, expected_ip=None):
    """0 成功，1 临时异常，2 服务器拒绝，3 网络已切换/无法确认。"""
    status = inspect_network(config, quick=bool(expected_ip))
    if expected_ip and status.ip != expected_ip:
        return LoginResult(3, "网络已经切换，取消本次认证，等待重新检测")
    if status.state in ("online", "authenticated"):
        return LoginResult(0, status.message)
    if status.state != "needs_login":
        return LoginResult(3, status.message)
    if status.portal_host and status.ac_id:
        config = {**config, "portal_host": status.portal_host, "ac_id": status.ac_id}
    username = config["username"] + config["domain"]
    print("[*] 已确认校园网，开始认证……", flush=True)
    print(f"[*] 当前认证入口：{config['portal_host']}，ac_id={config['ac_id']}", flush=True)
    stage = "确认客户端地址"
    with new_session() as session:
        try:
            _, real_ip = get_token(config, username, status.client_ip or status.ip, session, stage=stage)
            stage = "获取认证挑战码"
            token, _ = get_token(config, username, real_ip, session, stage=stage)
            if get_local_ip(config) != status.ip:
                return LoginResult(3, "网络已经切换，取消本次认证")
            hmd5 = get_md5(config["password"], token)
            encrypted = make_encrypted_info(
                username, config["password"], real_ip, config["ac_id"],
                config["enc_ver"], token, mode=config["encryption_mode"])
            checksum = make_checksum(token, username, hmd5, config["ac_id"],
                                     real_ip, config["n"], config["type"], encrypted)
            stage = "提交登录"
            response = _get(session, config,
                            f"http://{config['portal_host']}/cgi-bin/srun_portal",
                            timeout=(config["request_timeout"], config["login_timeout"]), stage=stage,
                            params={"callback": "jsonp", "action": "login",
                                    "username": username, "password": "{MD5}" + hmd5,
                                    "os": config["os"], "name": config["name"],
                                    "double_stack": 0, "chksum": checksum, "info": encrypted,
                                    "ac_id": config["ac_id"], "ip": real_ip,
                                    "n": config["n"], "type": config["type"]})
        except (requests.RequestException, RuntimeError) as error:
            if isinstance(error, requests.ConnectTimeout):
                detail = "连接认证服务器超时"
            elif isinstance(error, requests.ReadTimeout):
                detail = "等待认证服务器响应超时"
            elif isinstance(error, requests.HTTPError):
                detail = f"服务器返回 HTTP {getattr(error.response, 'status_code', '未知')}"
            elif isinstance(error, requests.ConnectionError):
                detail = "连接失败或连接被服务器中断"
            else:
                detail = "服务端未返回有效数据" if isinstance(error, RuntimeError) else type(error).__name__
            return LoginResult(1, f"{stage}失败：{detail}（入口 {config['portal_host']}，ac_id={config['ac_id']}）")
    data = _parse_jsonp(response.text)
    if data is None:
        return LoginResult(1, "认证响应无法识别，后台将稍后重试")
    if data.get("error") != "ok":
        error = re.sub(r"[^\w.-]", "", str(data.get("error", "unknown")))[:60]
        details = []
        for field in ("ecode", "error_msg", "suc_msg"):
            value = str(data.get(field, ""))
            if value and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", value) and value not in (
                    config["username"], config["password"], username, token):
                details.append(f"{field}={value}")
        detail = "，" + "，".join(details) if details else ""
        return LoginResult(2, f"服务器拒绝认证（{error}{detail}），后台暂停重试，请查看认证日志")
    # 登录已被服务器接受，立即显示结果；实际外网检查交给后台，不等待 DNS。
    return LoginResult(0, "校园网登录成功；后台继续检查联网情况，不重复认证")


def do_login(config):
    from monitor import AlreadyRunning, FileLock, RUNTIME
    try:
        with FileLock(RUNTIME / "login.lock"):
            result = login_once(config)
    except AlreadyRunning:
        print("[*] 已有认证任务正在运行，请等待该任务完成。", flush=True)
        return False
    print(("[OK] " if result.code == 0 else "[!] ") + result.message, flush=True)
    return result.code == 0


def main():
    parser = argparse.ArgumentParser(description="校园网登录及后台监测管理")
    parser.add_argument("--config", type=Path, default=ROOT / "config.json")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--start", action="store_true", help="启动后台监测")
    modes.add_argument("--stop", action="store_true", help="停止后台监测")
    modes.add_argument("--status", action="store_true", help="查看后台状态")
    modes.add_argument("--loop", action="store_true", help="前台监测（兼容旧命令）")
    modes.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--notice", choices=("online", "authenticated"), help=argparse.SUPPRESS)
    parser.add_argument("--expected-ip", help=argparse.SUPPRESS)
    parser.add_argument("--portal-host", help=argparse.SUPPRESS)
    parser.add_argument("--ac-id", help=argparse.SUPPRESS)
    args = parser.parse_args()
    for stream in (sys.stdout, sys.stderr):
        if stream and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    try:
        from monitor import manage, run_worker
        if args.stop or args.status:
            return manage("stop" if args.stop else "status", args.config)
        config = load_config(args.config)
        if args.portal_host or args.ac_id:
            context = portal_from_url(
                f"http://{args.portal_host}/srun_portal_pc?ac_id={args.ac_id}", config)
            if not context:
                raise ValueError("临时认证入口无效或不属于允许的校园网网段")
            config = {**config, **context}
            config["_portal_verified"] = True
        if args.start or args.loop:
            return manage("start" if args.start else "foreground", args.config)
        if args.worker:
            return run_worker(config, args.expected_ip, args.notice)
        return 0 if do_login(config) else 1
    except (OSError, ValueError) as error:
        message = str(error) if isinstance(error, ValueError) and not isinstance(error, json.JSONDecodeError) else "无法读取配置文件，请检查 config.json 的位置和 JSON 格式"
        print(f"[!] {message}", flush=True)
        if args.worker:
            time.sleep(15)
        return 2


if __name__ == "__main__":
    sys.exit(main())
