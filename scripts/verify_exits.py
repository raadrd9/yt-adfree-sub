#!/usr/bin/env python3
"""
True Exit-IP Verification Pipeline for v2rayNG (Xray-core backend).
Tests candidate VLESS / Trojan URIs by spawning headless Xray instances
and verifying that the ACTUAL EXIT IP geolocates to an ad-free YouTube country.
"""
import base64
import concurrent.futures
import json
import os
import re
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple

# Confirmed YouTube ad-free exit jurisdictions (MD removed per Google YPP list)
TARGET_EXIT_COUNTRIES = {"AL", "RU", "MC", "MN", "MM", "BS", "MR"}

PROTO_HTTP = "http" + "://"
PROTO_HTTPS = "https" + "://"
LOCALHOST = "127.0.0.1"

UPSTREAM_REPOS = [
    ("0xRadikal", "Free-v2ray-Configs", "main/Countries/Russia.txt"),
    ("0xRadikal", "Free-v2ray-Configs", "main/verified/configs.txt"),
    ("0xRadikal", "Free-v2ray-Configs", "main/all/configs.txt"),
    ("Alirewa", "V2ray-Configs", "main/config.txt"),
    ("Epodonios", "v2ray-configs", "main/All_Configs_Sub.txt"),
    ("mahdibland", "V2RayAggregator", "master/sub/sub_merge.txt"),
]

HINT_PATTERN = re.compile(
    r"(🇷🇺|🇦🇱|🇲🇨|🇲🇳|🇲🇲|🇧🇸|🇲🇷|russia|moscow|albania|monaco|mongolia|myanmar|(?<![a-zA-Z])(RU|AL|MC|MN|MM|BS|MR)(?![a-zA-Z]))",
    re.IGNORECASE,
)

MAX_WORKERS = 35
SOCK_TIMEOUT = 6
MAX_CANDIDATES = 1800


def build_source_urls() -> List[str]:
    env_urls = os.environ.get("SOURCE_URLS", "").strip()
    if env_urls:
        return [u.strip() for u in env_urls.splitlines() if u.strip()]
    base = PROTO_HTTPS + "raw.githubusercontent.com"
    return [f"{base}/{owner}/{repo}/{path}" for owner, repo, path in UPSTREAM_REPOS]


def fetch_lines(url: str) -> List[str]:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8", errors="ignore").strip()
            if "://" not in raw[:200]:
                try:
                    raw = base64.b64decode(raw + "===").decode("utf-8", errors="ignore")
                except Exception:
                    pass
            return [line.strip() for line in raw.splitlines() if line.strip() and not line.startswith("#")]
    except Exception:
        return []


def parse_vless_or_trojan(uri: str) -> Optional[Dict]:
    try:
        parsed = urllib.parse.urlsplit(uri)
        scheme = parsed.scheme.lower()
        if scheme not in ("vless", "trojan"):
            return None
        if "@" not in parsed.netloc:
            return None
        userinfo, hostport = parsed.netloc.rsplit("@", 1)
        user_id = urllib.parse.unquote(userinfo)
        if ":" in hostport and not hostport.endswith("]"):
            host, port_str = hostport.rsplit(":", 1)
            port = int(port_str)
        else:
            return None
        host = host.strip("[]")
        if not host or not (1 <= port <= 65535):
            return None

        params = dict(urllib.parse.parse_qsl(parsed.query))
        net_type = params.get("type", "tcp")
        security = params.get("security", "tls" if scheme == "trojan" else "none")

        stream_settings: Dict = {"network": net_type, "security": security}
        if security == "reality":
            stream_settings["realitySettings"] = {
                "serverName": params.get("sni", ""),
                "fingerprint": params.get("fp", "chrome"),
                "publicKey": params.get("pbk", ""),
                "shortId": params.get("sid", ""),
                "spiderX": params.get("spx", "/"),
            }
            if not stream_settings["realitySettings"]["publicKey"]:
                return None
        elif security == "tls":
            stream_settings["tlsSettings"] = {
                "serverName": params.get("sni", host),
                "fingerprint": params.get("fp", "chrome"),
                "allowInsecure": False,
            }

        if net_type == "grpc":
            stream_settings["grpcSettings"] = {
                "serviceName": params.get("serviceName", ""),
                "multiMode": params.get("mode") == "multi",
            }
        elif net_type == "ws":
            stream_settings["wsSettings"] = {
                "path": params.get("path", "/"),
                "headers": {"Host": params.get("host", host)},
            }
        elif net_type == "xhttp":
            stream_settings["xhttpSettings"] = {
                "path": params.get("path", "/"),
                "host": params.get("host", host),
                "mode": params.get("mode", "auto"),
            }

        if scheme == "vless":
            outbound = {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [{
                            "id": user_id,
                            "encryption": params.get("encryption", "none"),
                            "flow": params.get("flow", ""),
                        }],
                    }]
                },
                "streamSettings": stream_settings,
            }
        else:
            outbound = {
                "tag": "proxy",
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": host,
                        "port": port,
                        "password": user_id,
                    }]
                },
                "streamSettings": stream_settings,
            }
        return outbound
    except Exception:
        return None


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((LOCALHOST, 0))
        return s.getsockname()[1]


def wait_for_port(port: int, timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((LOCALHOST, port), timeout=0.1):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def verify_single_node(uri: str) -> Optional[Tuple[int, str, str]]:
    outbound = parse_vless_or_trojan(uri)
    if not outbound:
        return None

    http_port = find_free_port()
    xray_cfg = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "tag": "http_in",
            "port": http_port,
            "listen": LOCALHOST,
            "protocol": "http",
        }],
        "outbounds": [outbound],
    }

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump(xray_cfg, tf)
        cfg_path = tf.name

    proc = None
    try:
        proc = subprocess.Popen(
            ["xray", "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )
        if not wait_for_port(http_port):
            return None

        proxy_url = f"{PROTO_HTTP}{LOCALHOST}:{http_port}"
        proxy_handler = urllib.request.ProxyHandler({
            "http": proxy_url,
            "https": proxy_url,
        })
        opener = urllib.request.build_opener(proxy_handler)

        # Round 1: Check Cloudflare trace true exit country
        t0 = time.monotonic()
        trace_url = PROTO_HTTPS + "cloudflare.com/cdn-cgi/trace"
        req1 = urllib.request.Request(
            trace_url,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        with opener.open(req1, timeout=SOCK_TIMEOUT) as r1:
            body1 = r1.read().decode("utf-8", errors="ignore")
        delay_ms = int((time.monotonic() - t0) * 1000)

        kv = dict(line.split("=", 1) for line in body1.splitlines() if "=" in line)
        exit_cc = kv.get("loc", "").strip().upper()
        exit_ip = kv.get("ip", "").strip()

        if exit_cc not in TARGET_EXIT_COUNTRIES:
            return None

        # Round 2: Verify Google generate_204 reachability through the exit
        probe_url = PROTO_HTTPS + "www.gstatic.com/generate_204"
        req2 = urllib.request.Request(
            probe_url,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        with opener.open(req2, timeout=SOCK_TIMEOUT) as r2:
            if r2.status not in (200, 204):
                return None

        base_uri = uri.split("#", 1)[0]
        clean_uri = f"{base_uri}#EXIT-{exit_cc} | {delay_ms}ms | {exit_ip[:12]}"
        return (delay_ms, exit_cc, clean_uri)
    except Exception:
        return None
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1.5)
            except subprocess.TimeoutExpired:
                proc.kill()
        if os.path.exists(cfg_path):
            os.remove(cfg_path)


def main() -> None:
    raw_pool: List[str] = []
    for url in build_source_urls():
        raw_pool.extend(fetch_lines(url))

    seen = set()
    prioritized: List[str] = []
    general: List[str] = []
    for uri in raw_pool:
        if not (uri.startswith("vless" + "://") or uri.startswith("trojan" + "://")):
            continue
        key = uri.split("#", 1)[0]
        if key in seen:
            continue
        seen.add(key)
        decoded_uri = urllib.parse.unquote(uri)
        if HINT_PATTERN.search(decoded_uri):
            prioritized.append(uri)
        else:
            general.append(uri)

    candidates = (prioritized + general)[:MAX_CANDIDATES]
    verified: List[Tuple[int, str, str]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        for res in pool.map(verify_single_node, candidates):
            if res is not None:
                verified.append(res)

    verified.sort(key=lambda x: x[0])
    os.makedirs("out", exist_ok=True)

    if verified:
        plain_lines = [item[2] for item in verified]
        plain_text = "\n".join(plain_lines) + "\n"
        b64_text = base64.b64encode(plain_text.encode("utf-8")).decode("utf-8")
        with open("out/sub.txt", "w", encoding="utf-8") as f:
            f.write(plain_text)
        with open("out/sub_base64.txt", "w", encoding="utf-8") as f:
            f.write(b64_text)
    print(f"Tested {len(candidates)} candidates ({len(prioritized)} hinted) -> {len(verified)} verified ad-free exit nodes.")


if __name__ == "__main__":
    main()
