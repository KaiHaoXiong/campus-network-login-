"""解析学校认证入口；只缓存已观察到的地址，不把旧 ac_id 当作发现结果。"""

import html
import ipaddress
import json
import os
from pathlib import Path
import re
import threading
from urllib.parse import parse_qs, urljoin, urlsplit

CACHE = Path(__file__).resolve().parent / ".runtime" / "portal_cache.json"


def trusted_host(host, config):
    try:
        address = ipaddress.IPv4Address(host)
        allowed = config.get("portal_networks") or [
            str(ipaddress.IPv4Network(config["portal_host"] + "/24", strict=False))]
        return any(address in ipaddress.IPv4Network(network) for network in allowed)
    except (ValueError, TypeError):
        return False


def portal_from_url(url, config):
    try:
        parsed = urlsplit(html.unescape(url))
        if (parsed.scheme != "http" or parsed.username or parsed.password or
                parsed.port not in (None, 80) or not trusted_host(parsed.hostname, config)):
            return None
        index = re.fullmatch(r"/index_([1-9][0-9]{0,5})\.html", parsed.path)
        if index:
            ac_id = index.group(1)
        elif parsed.path.startswith("/srun_portal"):
            ac_id = parse_qs(parsed.query).get("ac_id", [""])[0]
        else:
            return None
        if not re.fullmatch(r"[1-9][0-9]{0,5}", ac_id):
            return None
        return {"portal_host": parsed.hostname, "ac_id": ac_id}
    except (ValueError, TypeError):
        return None


def portal_client_ip(text):
    match = re.search(r'''\bCONFIG\s*=\s*\{[\s\S]{0,3000}?\bip\s*:\s*["']([^"']+)["']''', text)
    try:
        return str(ipaddress.IPv4Address(match.group(1))) if match else ""
    except ValueError:
        return ""


def portal_target(response, requested_url, config):
    """Location、Refresh、JS/HTML 中的 index_N 或 srun_portal 地址。"""
    text = html.unescape(response.text[:131072]).replace("\\/", "/")
    candidates = [response.headers.get("Location", "")]
    refresh = response.headers.get("Refresh", "")
    match = re.search(r"url\s*=\s*(.+)", refresh, re.I)
    if match:
        candidates.append(match.group(1).strip(" \"'"))
    # 已到达真正的 Portal 页面时，地址栏的 ac_id 才是该页正在使用的值。
    if portal_client_ip(text) and "Portal" in text:
        candidates.append(requested_url)
    candidates.extend(match.group() for match in re.finditer(
        r'''(?:http://[^\s<>"']+|/?index_[1-9][0-9]{0,5}\.html|/srun_portal[^\s<>"']+)''', text))
    for candidate in candidates:
        if not candidate:
            continue
        target = urljoin(requested_url, candidate)
        context = portal_from_url(target, config)
        if context:
            return target, context
    return None


def portal_from_response(response, requested_url, config):
    found = portal_target(response, requested_url, config)
    return found[1] if found else None


def cached_entries(config):
    try:
        data = json.loads(CACHE.read_text(encoding="utf-8"))
        return [entry for entry in data if isinstance(entry, dict) and
                portal_from_url(entry.get("url", ""), config) and
                isinstance(entry.get("source_ip"), str)][:16] if isinstance(data, list) else []
    except (OSError, ValueError, TypeError):
        return []


def remember_portal(config, source_ip, url):
    if not portal_from_url(url, config) or not source_ip:
        return
    try:
        ipaddress.IPv4Address(source_ip)
        entries = [entry for entry in cached_entries(config) if entry["source_ip"] != source_ip]
        entries.insert(0, {"source_ip": source_ip, "url": url})
        CACHE.parent.mkdir(exist_ok=True)
        temporary = CACHE.with_name(f"portal_cache.{os.getpid()}.{threading.get_ident()}.tmp")
        temporary.write_text(json.dumps(entries[:16], ensure_ascii=False), encoding="utf-8")
        temporary.replace(CACHE)
    except (OSError, ValueError):
        pass
