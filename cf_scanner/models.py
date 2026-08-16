"""
cf_scanner.models
==================
Tüm projede paylaşılan veri modelleri (dataclass).

ProxyConfig: vless / vmess / trojan / shadowsocks linklerinden çıkarılan
             ve configs.json içinde saklanan proxy yapılandırması.
ScanResult : Bir IP için tarama sonucu (ping, açık portlar, doğrulama detayı).
"""
from __future__ import annotations

import time
import uuid as uuidlib
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List


@dataclass
class ProxyConfig:
    # Genel
    id: str = field(default_factory=lambda: uuidlib.uuid4().hex[:8])
    name: str = "IsimsizConfig"
    protocol: str = "vless"          # vless | vmess | trojan | shadowsocks
    address: str = ""                # linkteki orijinal host/domain (referans amaçlı)
    port: int = 443

    # Kimlik bilgileri
    uid: str = ""                    # vless/vmess uuid  |  ss/trojan password buraya da yazılabilir
    password: str = ""               # trojan / shadowsocks password
    method: str = ""                 # shadowsocks method (aes-256-gcm vb.)
    alter_id: int = 0                # vmess legacy alterId
    vmess_security: str = "auto"     # vmess şifreleme (auto/aes-128-gcm/chacha20-poly1305/none)
    encryption: str = "none"         # vless encryption (her zaman none olmalı)
    flow: str = ""                   # xtls-rprx-vision vb. (yalnızca tcp+tls/reality)

    # Transport (network) ayarları
    network: str = "tcp"             # tcp | ws | grpc | xhttp
    security: str = "tls"            # none | tls | reality
    sni: str = ""
    host: str = ""                   # ws/xhttp Host header
    path: str = ""                   # ws/xhttp path
    service_name: str = ""           # grpc serviceName
    grpc_mode: str = "gun"           # gun | multi
    xhttp_mode: str = "auto"         # auto | packet-up | stream-up | stream-one
    xhttp_extra: Optional[Dict[str, Any]] = None  # xhttpSettings.extra (padding/xmux/vb.)

    # TLS / sertifika
    alpn: List[str] = field(default_factory=list)
    fingerprint: str = ""            # utls fingerprint (chrome/firefox/edge/random...)
    allow_insecure: bool = False     # NOT: yeni Xray-core'da kullanılmıyor, bilgi amaçlı saklanır
    pinned_cert_sha256: str = ""     # pcs
    verify_peer_cert_by_name: str = ""  # vcn

    # REALITY
    reality_public_key: str = ""
    reality_short_id: str = ""
    reality_spider_x: str = ""

    # Fragment (Finalmask) - {"packets":..,"length":..,"interval":..}
    fragment: Optional[Dict[str, str]] = None

    raw_link: str = ""
    created_at: float = field(default_factory=time.time)

    # ---- yardımcılar -----------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ProxyConfig":
        valid_keys = {f for f in cls.__dataclass_fields__.keys()}
        filtered = {k: v for k, v in d.items() if k in valid_keys}
        return cls(**filtered)

    def is_quic_only_xhttp(self) -> bool:
        """True ise bu config xhttp üzerinde SADECE ALPN=h3 ile çalışır, yani
        Xray-core bunu TCP değil GERÇEK QUIC/UDP ile taşır (bkz. Xray-core
        discussion #4113: '若 alpn 仅有 h3 则使用 quic-go H3'). Bu durumda
        TCP tabanlı 'raw' TLS-handshake modu bu configi ANLAMLI şekilde test
        edemez; %100 doğrulama için 'xray' tam-tünel modu gerekir."""
        return self.network == "xhttp" and self.alpn == ["h3"]

    def short_desc(self) -> str:
        bits = [self.protocol.upper(), self.network]
        if self.security != "none":
            bits.append(self.security)
        if self.fragment:
            bits.append("fragment✓")
        return " / ".join(bits)


@dataclass
class ScanResult:
    ip: str
    ping_ms: int = 0
    open_ports: List[int] = field(default_factory=list)
    verified: bool = False           # xray-core ile tam tünel testi geçti mi
    verify_method: str = ""          # "xray" | "raw" | "cloudflare"
    verified_port: Optional[int] = None
    tunnel_latency_ms: Optional[int] = None
    protocol: str = ""
    config_name: str = ""
    checked_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
