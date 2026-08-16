"""
cf_scanner.link_parser
=======================
vless:// , vmess:// , trojan:// , ss://  paylaşım linklerini ProxyConfig'e çevirir.

Fragment (Finalmask) önceliklendirmesi:
  1) 'fm' parametresi varsa (Xray-core resmi paylaşım linki standardı,
     bkz. https://github.com/XTLS/Xray-core/discussions/716) bu öncelikli kullanılır.
     Format: {"tcp":[{"type":"fragment","settings":{"packets":..,"length":..,"interval"|"delay":..}}], "udp":[...]}
  2) 'fm' yoksa eski/legacy 'fragment=length,interval,packets,...' parametresi
     best-effort olarak ayrıştırılır (istemciler arası sıralama standardı net
     olmadığı için sayısal olmayan token "packets" kabul edilir).
"""
from __future__ import annotations

import base64
import json
import re
from typing import Optional, Dict, Any
from urllib.parse import urlsplit, parse_qs, unquote

from .models import ProxyConfig

_RANGE_RE = re.compile(r"^\d+(-\d+)?$")


def _b64_decode(s: str) -> str:
    s = s.strip()
    # urlsafe / standard ve eksik padding toleranslı decode
    s = s.replace("-", "+").replace("_", "/")
    pad = (-len(s)) % 4
    s += "=" * pad
    return base64.b64decode(s).decode("utf-8", errors="ignore")


def _first(qs: Dict[str, list], key: str, default: str = "") -> str:
    v = qs.get(key)
    return v[0] if v else default


def _sanitize_json_numbers(obj):
    """1000000.0 -> 1000000 (recursive).

    Birçok abonelik/QR üretici xhttp 'extra' JSON'ını Python/JS tarafında
    üretirken tam sayıları float olarak yazıyor (örn. 1000000.0). Xray-core'un
    Go JSON çözümleyicisi RangeConfig alanları (scMaxEachPostBytes,
    scMinPostsIntervalMs, xmux.* vb.) için ondalıklı sayıyı KABUL ETMİYOR ve
    'Invalid integer range, expected either string of form "1-2" or plain
    integer' hatasıyla xray-core'un TAMAMEN başlamamasına neden oluyor
    (xray-core v26.7.11 ile doğrulandı). Bu yüzden 'extra' bloğunu olduğu gibi
    JSON'a kopyalamak yerine önce bu sanitizasyondan geçiriyoruz."""
    if isinstance(obj, dict):
        return {k: _sanitize_json_numbers(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_json_numbers(v) for v in obj]
    if isinstance(obj, float) and obj.is_integer():
        return int(obj)
    return obj


def parse_xhttp_extra(qs: Dict[str, list]) -> Optional[Dict[str, Any]]:
    """Linkteki 'extra' parametresinden (xhttpSettings.extra) sözlük üretir.
    Bilinmeyen/eski alan adları (örn. eski 'scMaxConcurrentPosts') olduğu gibi
    bırakılır — Xray-core'un Go json çözümleyicisi tanımadığı alanları
    sessizce yok sayar, bu yüzden beyaz liste tutmaya gerek yok; asıl kritik
    olan sayısal tiplerin doğru olması (bkz. _sanitize_json_numbers)."""
    raw = _first(qs, "extra")
    if not raw:
        return None
    try:
        data = json.loads(unquote(raw)) if "%" in raw else json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(data, dict) or not data:
        return None
    return _sanitize_json_numbers(data)


def parse_fragment(qs: Dict[str, list]) -> Optional[Dict[str, str]]:
    """Linkteki fm / fragment parametrelerinden Xray-core uyumlu
    {'packets':.., 'length':.., 'interval':..} sözlüğü üretir."""
    fm_raw = _first(qs, "fm")
    if fm_raw:
        try:
            fm_data = json.loads(unquote(fm_raw)) if "%" in fm_raw else json.loads(fm_raw)
        except (json.JSONDecodeError, TypeError):
            fm_data = None
        if isinstance(fm_data, dict):
            for layer in ("tcp", "udp"):
                for item in fm_data.get(layer, []) or []:
                    if isinstance(item, dict) and item.get("type") == "fragment":
                        s = item.get("settings", {}) or {}
                        return {
                            "packets": str(s.get("packets", "tlshello")),
                            "length": str(s.get("length", "100-200")),
                            "interval": str(s.get("interval", s.get("delay", "10-20"))),
                        }

    frag_raw = _first(qs, "fragment")
    if frag_raw and frag_raw.lower() not in ("", "0", "null", "none", "false"):
        parts = [p.strip() for p in frag_raw.split(",") if p.strip()]
        numeric = [p for p in parts if _RANGE_RE.fullmatch(p)]
        non_numeric = [p for p in parts if not _RANGE_RE.fullmatch(p) and p.lower() != "null"]
        packets = non_numeric[0] if non_numeric else (numeric[0] if numeric else "1-3")
        remaining_numeric = [p for p in numeric if p != packets]
        length = remaining_numeric[0] if len(remaining_numeric) > 0 else "100-200"
        interval = remaining_numeric[1] if len(remaining_numeric) > 1 else "10-20"
        return {"packets": packets, "length": length, "interval": interval}

    return None


def _common_stream_fields(cfg: ProxyConfig, qs: Dict[str, list]) -> None:
    net = _first(qs, "type", cfg.network) or "tcp"
    cfg.network = "xhttp" if net == "splithttp" else net
    cfg.security = _first(qs, "security", "none") or "none"
    cfg.sni = _first(qs, "sni") or _first(qs, "peer")
    cfg.host = _first(qs, "host")
    path = _first(qs, "path")
    cfg.path = unquote(path) if path else ""
    cfg.service_name = _first(qs, "serviceName")
    # DÜZELTME: 'mode' parametresi hem grpc (gun/multi) hem xhttp
    # (auto/packet-up/stream-up/stream-one) linklerinde ortak kullanılıyor.
    # Eskiden ikisi de aynı ham değeri alıyordu (örn. bir xhttp linkindeki
    # mode=packet-up, kullanılmasa da grpc_mode alanına da yazılıyordu).
    # Artık her alan sadece kendi network türü için ilgili linkten okunuyor.
    mode_raw = _first(qs, "mode")
    cfg.grpc_mode = (mode_raw if cfg.network == "grpc" else "") or "gun"
    cfg.xhttp_mode = (mode_raw if cfg.network == "xhttp" else "") or "auto"
    cfg.xhttp_extra = parse_xhttp_extra(qs) if cfg.network == "xhttp" else None
    alpn_raw = _first(qs, "alpn")
    cfg.alpn = [a for a in alpn_raw.split(",") if a] if alpn_raw else []
    cfg.fingerprint = _first(qs, "fp")
    cfg.allow_insecure = _first(qs, "allowinsecure", "0") in ("1", "true", "True")
    cfg.pinned_cert_sha256 = _first(qs, "pcs")
    cfg.verify_peer_cert_by_name = _first(qs, "vcn")
    cfg.reality_public_key = _first(qs, "pbk")
    cfg.reality_short_id = _first(qs, "sid")
    cfg.reality_spider_x = _first(qs, "spx")
    cfg.fragment = parse_fragment(qs)


def parse_vless(link: str) -> Optional[ProxyConfig]:
    if not link.startswith("vless://"):
        return None
    u = urlsplit(link)
    if not u.hostname:
        return None
    qs = parse_qs(u.query)
    cfg = ProxyConfig(
        protocol="vless",
        address=u.hostname,
        port=u.port or 443,
        uid=u.username or "",
        encryption=_first(qs, "encryption", "none") or "none",
        flow=_first(qs, "flow"),
        raw_link=link,
    )
    _common_stream_fields(cfg, qs)
    if not cfg.path:
        # gRPC bazı linklerde 'serviceName' yerine path kullanır
        cfg.path = unquote(_first(qs, "serviceName")) if cfg.network == "grpc" else cfg.path
    name = unquote(u.fragment) if u.fragment else ""
    cfg.name = name or "IsimsizConfig"
    return cfg


def parse_vmess(link: str) -> Optional[ProxyConfig]:
    if not link.startswith("vmess://"):
        return None
    body = link[len("vmess://"):]
    # 1) Klasik v2rayN base64-JSON formatı (en yaygın)
    try:
        decoded = _b64_decode(body.split("#")[0])
        data = json.loads(decoded)
        cfg = ProxyConfig(
            protocol="vmess",
            address=data.get("add", ""),
            port=int(data.get("port", 443) or 443),
            uid=data.get("id", ""),
            alter_id=int(data.get("aid", 0) or 0),
            vmess_security=data.get("scy", "auto") or "auto",
            network=("xhttp" if data.get("net") == "splithttp" else data.get("net", "tcp")) or "tcp",
            security="tls" if data.get("tls") in ("tls", "reality") else "none",
            sni=data.get("sni", "") or data.get("host", ""),
            host=data.get("host", ""),
            path=data.get("path", ""),
            service_name=data.get("path", "") if data.get("net") == "grpc" else "",
            fingerprint=data.get("fp", ""),
            alpn=[a for a in (data.get("alpn", "") or "").split(",") if a],
            name=data.get("ps", "IsimsizConfig"),
            raw_link=link,
        )
        if data.get("tls") == "reality":
            cfg.security = "reality"
        return cfg
    except Exception:
        pass

    # 2) URI-tarzı (vless benzeri) - bazı yeni istemciler bu formatı da üretiyor
    try:
        u = urlsplit(link)
        qs = parse_qs(u.query)
        cfg = ProxyConfig(
            protocol="vmess",
            address=u.hostname or "",
            port=u.port or 443,
            uid=u.username or "",
            alter_id=int(_first(qs, "alterId", "0") or 0),
            vmess_security=_first(qs, "encryption", "auto") or "auto",
            raw_link=link,
        )
        _common_stream_fields(cfg, qs)
        cfg.name = unquote(u.fragment) if u.fragment else "IsimsizConfig"
        return cfg
    except Exception:
        return None


def parse_trojan(link: str) -> Optional[ProxyConfig]:
    if not link.startswith("trojan://"):
        return None
    u = urlsplit(link)
    if not u.hostname:
        return None
    qs = parse_qs(u.query)
    cfg = ProxyConfig(
        protocol="trojan",
        address=u.hostname,
        port=u.port or 443,
        password=u.username or "",
        raw_link=link,
    )
    _common_stream_fields(cfg, qs)
    if cfg.security == "none":
        cfg.security = "tls"  # trojan varsayılan olarak tls bekler
    cfg.name = unquote(u.fragment) if u.fragment else "IsimsizConfig"
    return cfg


def parse_shadowsocks(link: str) -> Optional[ProxyConfig]:
    if not link.startswith("ss://"):
        return None
    u = urlsplit(link)
    name = unquote(u.fragment) if u.fragment else "IsimsizConfig"
    body = link[len("ss://"):].split("#")[0]

    method, password, host, port = "", "", "", 8388
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        try:
            userinfo = _b64_decode(userinfo) if ":" not in userinfo else userinfo
        except Exception:
            pass
        if ":" in userinfo:
            method, password = userinfo.split(":", 1)
        host_part, _, port_part = hostport.partition(":")
        port_part = port_part.split("/")[0].split("?")[0]
        host = host_part
        try:
            port = int(port_part) if port_part else 8388
        except ValueError:
            port = 8388
    else:
        try:
            decoded = _b64_decode(body)
            # method:password@host:port
            userinfo, hostport = decoded.rsplit("@", 1)
            method, password = userinfo.split(":", 1)
            host, port_s = hostport.split(":")
            port = int(port_s)
        except Exception:
            return None

    if not host or not method:
        return None

    return ProxyConfig(
        protocol="shadowsocks",
        address=host,
        port=port,
        method=method,
        password=password,
        network="tcp",
        security="none",
        name=name,
        raw_link=link,
    )


def parse_link(link: str) -> Optional[ProxyConfig]:
    """Hangi protokol olursa olsun otomatik algılayıp ayrıştırır."""
    link = link.strip()
    if link.startswith("vless://"):
        return parse_vless(link)
    if link.startswith("vmess://"):
        return parse_vmess(link)
    if link.startswith("trojan://"):
        return parse_trojan(link)
    if link.startswith("ss://"):
        return parse_shadowsocks(link)
    return None
