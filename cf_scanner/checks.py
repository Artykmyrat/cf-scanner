"""
cf_scanner.checks
==================
TCP port tarama + TLS handshake testi + Cloudflare tespiti.

DÜZELTMELER (bu sürümde):
  1) scan_ports() SİRALIYDI → KALDIRILDI.
     first_open_port() ile DEĞİŞTİRİLDİ: tüm portlar PARALEL taranır.
     Eski: 11 port × 1.2s = 13.2s kötü durum / IP
     Yeni: tüm portlar aynı anda → max 0.8s / IP

  2) check_raw_tls() KALDIRILDI.
     check_tls_handshake() ile DEĞİŞTİRİLDİ: HTTP isteği GÖNDERMEZ,
     sadece TLS el sıkışmasını doğrular.
     Eski: HTTP/1.1 GET gönderiyordu → xHTTP/gRPC bu isteği reddeder
           → xHTTP için daima false negative üretiyordu.
     Yeni: TLS katmanı çalışıyor mu? Tüm transport türleri için geçerli.
"""
from __future__ import annotations

import asyncio
import ssl
import time
from typing import Dict, List, Optional, Tuple

import aiohttp


async def tcp_ping(ip: str, port: int, timeout: float = 0.8) -> Optional[int]:
    """TCP bağlantısı kurulabiliyorsa ms cinsinden gecikme, aksi hâlde None."""
    start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        ms = int((time.monotonic() - start) * 1000)
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=0.3)
        except Exception:
            pass
        return ms
    except Exception:
        return None


async def first_open_port(
    ip: str,
    ports: List[int],
    timeout: float = 0.8,
) -> Optional[Tuple[int, int]]:
    """Tüm portları PARALEL olarak tarar.
    İlk yanıt veren portun (port, ping_ms) ikilisini döner, hiçbiri açık
    değilse None döner. Bulunca kalan tasklar iptal edilir — boşa CPU yok.
    """
    if not ports:
        return None
    if len(ports) == 1:
        ms = await tcp_ping(ip, ports[0], timeout=timeout)
        return (ports[0], ms) if ms is not None else None

    tasks: Dict[asyncio.Task, int] = {
        asyncio.create_task(tcp_ping(ip, p, timeout=timeout)): p for p in ports
    }
    pending = set(tasks.keys())
    found: Optional[Tuple[int, int]] = None
    try:
        while pending and found is None:
            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED
            )
            for t in done:
                port = tasks[t]
                try:
                    ms = t.result()
                except Exception:
                    ms = None
                if ms is not None and found is None:
                    found = (port, ms)
                    for rem in pending:
                        rem.cancel()
                    pending.clear()
    except asyncio.CancelledError:
        for t in list(pending):
            t.cancel()
        raise
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
    return found


async def check_cloudflare(
    ip: str,
    port: int,
    sni: str = "",
    timeout: float = 5.0,
) -> bool:
    """/cdn-cgi/trace ile IP'nin Cloudflare arkasında olduğunu doğrular.
    sni verilirse Host başlığı olarak kullanılır — CDN yönlendirmesi için kritik."""
    url = f"https://{ip}:{port}/cdn-cgi/trace"
    connector = aiohttp.TCPConnector(ssl=False, force_close=True, limit=1)
    headers = {"Host": sni} if sni else {}
    try:
        async with aiohttp.ClientSession(connector=connector) as sess:
            async with sess.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=False,
            ) as resp:
                server = resp.headers.get("Server", "").lower()
                cf_ray = "cf-ray" in resp.headers
                try:
                    text = (await resp.text(errors="ignore")).lower()
                except Exception:
                    text = ""
                return "cloudflare" in server or cf_ray or "fl=" in text
    except Exception:
        return False


async def check_tls_handshake(
    ip: str,
    port: int,
    sni: str,
    alpn: Optional[List[str]] = None,
    timeout: float = 5.0,
) -> bool:
    """Sadece TLS el sıkışmasının başarılı olup olmadığını kontrol eder.

    Raw mod (Xray-Core kapalı) için kullanılır. HTTP isteği GÖNDERMEZ.

    Neden HTTP göndermiyoruz:
      - xHTTP endpointleri HTTP/1.1 isteklerini reddeder (HTTP/2 beklerler).
      - gRPC endpointleri de HTTP/1.1'i reddeder (content-type: application/grpc gerekir).
      - Önceki check_raw_tls() bu yüzden xHTTP ve gRPC için
        %100 false negative üretiyordu.

    TLS el sıkışması başarılıysa sunucu SNI'yi kabul etti demektir.
    Cloudflare edge IP'leri için bu iyi bir 'çalışabilir' sinyalidir.
    Kesin (%100) doğrulama için Xray-Core modu kullanılmalıdır.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        ctx.set_alpn_protocols(alpn)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni or ip),
            timeout=timeout,
        )
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
        except Exception:
            pass
        return True
    except Exception:
        return False
