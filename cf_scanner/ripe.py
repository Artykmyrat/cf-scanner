"""
cf_scanner.ripe
================
RIPEstat API üzerinden bir ASN'e ait duyurulmuş (announced) IPv4 prefixlerini
çeker, /24'ten büyük blokları /24'e böler ve IP üretici (generator) sağlar.

scan.go'daki getPrefixesFromRIPE + splitTo24 mantığının doğrudan Python karşılığı,
ipaddress modülü ile çok daha güvenilir/temiz şekilde.
"""
from __future__ import annotations

import ipaddress
from typing import List

import aiohttp

RIPE_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"


async def fetch_prefixes(asn: str, timeout: int = 20) -> List[str]:
    """Verilen ASN için RIPEstat'tan duyurulmuş IPv4 prefix listesini döner.
    Örn: AS13335 (Cloudflare) -> ['1.1.1.0/24', '104.16.0.0/13', ...]
    """
    asn_clean = asn.upper().replace("AS", "").strip()
    url = RIPE_URL.format(asn=asn_clean)
    prefixes: List[str] = []
    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            resp.raise_for_status()
            data = await resp.json()
    for item in data.get("data", {}).get("prefixes", []):
        prefix = item.get("prefix", "")
        # Sadece IPv4 ile ilgileniyoruz (Cloudflare edge IP taraması için)
        if prefix and ":" not in prefix:
            prefixes.append(prefix)
    return prefixes


def split_to_24(prefixes: List[str]) -> List[ipaddress.IPv4Network]:
    """24'ten büyük (örn /16, /13) blokları /24 alt ağlara böler.
    24 veya daha küçük (ör /28) bloklar olduğu gibi bırakılır."""
    out: List[ipaddress.IPv4Network] = []
    for p in prefixes:
        try:
            net = ipaddress.ip_network(p, strict=False)
        except ValueError:
            continue
        if not isinstance(net, ipaddress.IPv4Network):
            continue
        if net.prefixlen < 24:
            out.extend(net.subnets(new_prefix=24))
        else:
            out.append(net)
    return out


def count_hosts(networks: List[ipaddress.IPv4Network]) -> int:
    return sum(n.num_addresses for n in networks)


def iter_ips(networks: List[ipaddress.IPv4Network]):
    """Tüm /24 (veya daha küçük) bloklardaki HER IP'yi tek tek üretir.
    Not: Cloudflare gibi CDN bloklarında ağ/broadcast adresleri de (.0 / .255)
    gerçek kullanılabilir edge IP'leri olabileceğinden .hosts() yerine bilerek
    tam ağ aralığı (net) kullanılıyor — eksiksiz tarama için."""
    for net in networks:
        for ip in net:
            yield str(ip)
