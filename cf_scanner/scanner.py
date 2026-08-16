"""
cf_scanner.scanner
====================
İki aşamalı "huni" mimarisi:

  Üretici → [tcp_q] → TCP İşçiler (port tarar) → [deep_q] → Derin Doğrulama İşçileri

DÜZELTMELER (bu sürümde):

1) İKİ BAĞIMSIZ AŞAMA:
   Eski tek-havuz mimarisinde TCP ve derin doğrulama aynı işçileri paylaşıyordu.
   Derin doğrulama (5-15 sn/IP) yavaşlayınca TCP (0.8 sn/IP) da bloklanıyordu.
   Artık TCP işçileri (250 adet, hızlı) ve derin doğrulama işçileri (30-60, yavaş)
   tamamen ayrı kuyruklarla çalışır. deep_q dolunca backpressure ile TCP yavaşlar —
   sistem otomatik olarak en yavaş aşamanın hızına ayarlanır.

2) ANLIK DURDURMA:
   _stop_event (asyncio.Event) + Task.cancel() kombinasyonu.
   TCP işçileri 0.4 sn zaman aşımlı kuyruk okur, her döngüde stop_event kontrol eder.
   Derin işçiler 0.5 sn zaman aşımlıdır. Task.cancel() ile tüm await noktaları
   anında kesilir. Toplam dur süresi: < 1 sn.

3) SENTINEL YÖNETİMİ DÜZELTİLDİ:
   Üretici iptal olsa bile finally bloğu sentinel gönderir.
   Tüm TCP işçileri bitince ayrı bir görev derin işçilere sentinel gönderir.
   Eski kodda üretici iptal olunca sentinel hiç gitmiyordu → consumer'lar askıda kalıyordu.

4) TRANSPORT-AWARE RAW TEST:
   xHTTP/gRPC için h2 ALPN otomatik eklenerek check_tls_handshake() çağrılır.
   Eski check_raw_tls() HTTP/1.1 gönderdiği için xHTTP'de false negative üretiyordu.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass, field
from typing import Optional, List, Iterable, Dict, Set

from .models import ProxyConfig, ScanResult
from .checks import first_open_port, check_cloudflare, check_tls_handshake
from .xray_manager import XrayCoreManager
from .cache_store import BadIPCache

MODES = ("cloudflare", "raw", "xray")
BAD_CACHE_FLUSH_EVERY = 100


@dataclass
class ScanStats:
    total: int = 0
    scanned: int = 0
    alive: int = 0
    verified: int = 0
    skipped_known_bad: int = 0
    skipped_resumed: int = 0
    start_time: float = field(default_factory=time.monotonic)
    last_found_ips: List[str] = field(default_factory=list)

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.start_time

    @property
    def speed(self) -> float:
        el = self.elapsed
        return self.scanned / el if el > 0 else 0.0

    @property
    def eta_seconds(self) -> Optional[float]:
        sp = self.speed
        if sp <= 0 or self.total <= 0:
            return None
        remaining = max(self.total - self.scanned, 0)
        return remaining / sp


def load_existing_results(path: str) -> List[ScanResult]:
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        return [ScanResult(**d) for d in raw]
    except (json.JSONDecodeError, OSError, TypeError):
        return []


class Scanner:
    def __init__(
        self,
        ips: Iterable[str],
        total: int,
        mode: str,
        ports: List[int],
        cfg: Optional[ProxyConfig] = None,
        xray_manager: Optional[XrayCoreManager] = None,
        num_workers: int = 250,       # TCP işçi sayısı
        deep_concurrency: int = 40,   # Derin doğrulama işçi sayısı
        result_path: str = "cf_ips.json",
        autosave_every: int = 5,
        max_results: Optional[int] = None,
        bad_cache: Optional[BadIPCache] = None,
        context_key: str = "default",
        existing_results: Optional[List[ScanResult]] = None,
        tcp_timeout: float = 0.8,
        tls_timeout: float = 5.0,
    ):
        if mode not in MODES:
            raise ValueError(f"Geçersiz mod: {mode}")
        if mode in ("raw", "xray") and cfg is None:
            raise ValueError(f"'{mode}' modu için bir proxy config gereklidir")
        if mode == "xray" and xray_manager is None:
            raise ValueError("'xray' modu için XrayCoreManager gereklidir")

        self.ips = ips
        self.mode = mode
        self.ports = ports
        self.cfg = cfg
        self.xray_manager = xray_manager
        self.num_workers = num_workers
        self.deep_concurrency = deep_concurrency
        self.result_path = result_path
        self.autosave_every = autosave_every
        self.max_results = max_results
        self.bad_cache = bad_cache
        self.context_key = context_key

        self.tcp_timeout = tcp_timeout
        self.tls_timeout = tls_timeout

        self.stats = ScanStats(total=total)
        self.results: List[ScanResult] = list(existing_results or [])
        self.stats.verified = len(self.results)
        self._already_done_ips: Set[str] = {r.ip for r in self.results}

        # Derin doğrulama aşamasındaki IP'ler {ip: başlangıç_zamanı}
        self.in_progress: Dict[str, float] = {}

        self.finished = asyncio.Event()
        self._stop_event = asyncio.Event()   # Dur sinyali
        self._stop_fill = asyncio.Event()    # max_results'a ulaşıldı
        self._tasks: List[asyncio.Task] = []
        self._unsaved_count = 0
        self._bad_unsaved = 0

    # ------------------------------------------------------------------
    def request_stop(self) -> None:
        """Anlık durdurma: Event sinyali + tüm görevlerin iptal edilmesi."""
        self._stop_event.set()
        for t in self._tasks:
            if not t.done():
                t.cancel()

    @property
    def stop_requested(self) -> bool:
        return self._stop_event.is_set()

    # ------------------------------------------------------------------
    def _save_results(self) -> None:
        tmp = self.result_path + ".tmp"
        os.makedirs(
            os.path.dirname(os.path.abspath(self.result_path)) or ".", exist_ok=True
        )
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(
                [r.to_dict() for r in self.results], f, indent=2, ensure_ascii=False
            )
        os.replace(tmp, self.result_path)

    def _add_result(self, res: ScanResult) -> None:
        self.results.append(res)
        self.stats.verified += 1
        self.stats.last_found_ips.append(res.ip)
        self.stats.last_found_ips = self.stats.last_found_ips[-15:]
        self._unsaved_count += 1
        if self._unsaved_count >= self.autosave_every:
            self._save_results()
            self._unsaved_count = 0
        if self.max_results and len(self.results) >= self.max_results:
            self._stop_fill.set()

    def _mark_bad(self, ip: str) -> None:
        if not self.bad_cache:
            return
        self.bad_cache.mark_bad(self.context_key, ip)
        self._bad_unsaved += 1
        if self._bad_unsaved >= BAD_CACHE_FLUSH_EVERY:
            self.bad_cache.flush()
            self._bad_unsaved = 0

    # ------------------------------------------------------------------
    async def _deep_verify(self, ip: str, port: int, ping: int) -> bool:
        """Moda ve transport türüne göre doğru testi uygular."""
        if self.mode == "cloudflare":
            sni = (self.cfg.sni or self.cfg.address) if self.cfg else ""
            ok = await check_cloudflare(ip, port, sni=sni, timeout=self.tls_timeout)
            if ok:
                self._add_result(ScanResult(
                    ip=ip, ping_ms=ping, open_ports=[port], verified=True,
                    verify_method="cloudflare", verified_port=port,
                ))
            return ok

        elif self.mode == "raw":
            # Transport türünden bağımsız TLS testi — HTTP GÖNDERMİYOR.
            if self.cfg:
                sni = self.cfg.sni or self.cfg.address
                alpn: List[str] = list(self.cfg.alpn) if self.cfg.alpn else []
                # DÜZELTME: sadece link'te ALPN hiç belirtilmemişse varsayılan
                # h2 eklenir. Önceden burada da h3-only configlere zorla h2
                # ekleniyordu; bu, xhttp_manager.py'deki ile aynı hataydı ve
                # h3/QUIC configlerin ham modda hep yanlış ALPN ile test
                # edilmesine yol açıyordu (bkz. xray_manager._tls_block).
                if not alpn and self.cfg.network in ("grpc", "xhttp"):
                    alpn = ["h2"]
                transport_label = self.cfg.network
            else:
                sni, alpn, transport_label = "", [], "tcp"

            ok = await check_tls_handshake(ip, port, sni, alpn=alpn, timeout=self.tls_timeout)
            if ok:
                self._add_result(ScanResult(
                    ip=ip, ping_ms=ping, open_ports=[port], verified=True,
                    verify_method=f"tls({transport_label})",
                    verified_port=port,
                    protocol=self.cfg.protocol if self.cfg else "",
                    config_name=self.cfg.name if self.cfg else "",
                ))
            return ok

        elif self.mode == "xray":
            tr = await self.xray_manager.verify(self.cfg, ip)
            if tr.success:
                self._add_result(ScanResult(
                    ip=ip, ping_ms=ping, open_ports=[port], verified=True,
                    verify_method="xray-tunnel", verified_port=port,
                    tunnel_latency_ms=tr.latency_ms,
                    protocol=self.cfg.protocol,
                    config_name=self.cfg.name,
                ))
            return tr.success

        return False

    # ------------------------------------------------------------------
    async def run(self) -> List[ScanResult]:
        # Aşama-1 kuyruğu: IP'ler için (üretici → TCP işçiler)
        tcp_q: asyncio.Queue = asyncio.Queue(maxsize=self.num_workers * 2)
        # Aşama-2 kuyruğu: (ip, port, ping) üçlüsü (TCP → derin doğrulama)
        deep_q: asyncio.Queue = asyncio.Queue(maxsize=self.deep_concurrency * 4)

        # Kaç TCP işçisinin tamamlandığını sayar (asyncio tek-iş parçacıklı → lock gerekmez)
        tcp_done_count = [0]
        tcp_all_done = asyncio.Event()

        should_stop = self._stop_event

        # ----------------------------------------------------------------
        async def producer() -> None:
            try:
                for ip in self.ips:
                    if should_stop.is_set() or self._stop_fill.is_set():
                        break
                    # Önceki sonuçtan veya bad cache'ten atlama
                    if ip in self._already_done_ips:
                        self.stats.scanned += 1
                        self.stats.skipped_resumed += 1
                        continue
                    if self.bad_cache and self.bad_cache.is_known_bad(
                        self.context_key, ip
                    ):
                        self.stats.scanned += 1
                        self.stats.skipped_known_bad += 1
                        continue
                    await tcp_q.put(ip)  # Kuyruk dolunca bekler (doğal geri-basınç)
            except asyncio.CancelledError:
                pass  # İptal sinyali geldi, sentinel gönder ve çık
            finally:
                # İptal olsa bile TCP işçileri için sentinel gönder
                for _ in range(self.num_workers):
                    try:
                        tcp_q.put_nowait(None)
                    except asyncio.QueueFull:
                        break  # İşçiler de iptal ediliyor, yeterli

        # ----------------------------------------------------------------
        async def tcp_worker() -> None:
            try:
                while True:
                    if should_stop.is_set():
                        break
                    try:
                        ip = await asyncio.wait_for(tcp_q.get(), timeout=0.4)
                    except asyncio.TimeoutError:
                        continue  # Periyodik stop_event kontrolü
                    if ip is None:
                        break   # Sentinel: üretici bitti
                    if should_stop.is_set() or self._stop_fill.is_set():
                        continue
                    try:
                        result = await first_open_port(ip, self.ports)
                        self.stats.scanned += 1
                        if result is not None:
                            port, ping_ms = result
                            self.stats.alive += 1
                            if not (
                                should_stop.is_set() or self._stop_fill.is_set()
                            ):
                                # Derin kuyruk dolunca burada bekler (backpressure)
                                await deep_q.put((ip, port, ping_ms))
                        else:
                            self._mark_bad(ip)
                    except asyncio.CancelledError:
                        break
                    except Exception:
                        self.stats.scanned += 1
            finally:
                # Kaç TCP işçisinin bittiğini sayıyoruz
                tcp_done_count[0] += 1
                if tcp_done_count[0] >= self.num_workers:
                    tcp_all_done.set()

        # ----------------------------------------------------------------
        async def deep_sentinel_sender() -> None:
            """Tüm TCP işçileri tamamlanınca derin işçilere durdurma sinyali gönderir."""
            try:
                await tcp_all_done.wait()
            except asyncio.CancelledError:
                # İptal olduk ama derin işçiler de iptal ediliyor, sorun yok
                return
            for _ in range(self.deep_concurrency):
                try:
                    deep_q.put_nowait(None)
                except asyncio.QueueFull:
                    break

        # ----------------------------------------------------------------
        async def deep_worker() -> None:
            while True:
                if should_stop.is_set():
                    break
                try:
                    item = await asyncio.wait_for(deep_q.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    # TCP tamamen bittiyse ve kuyruk boşsa çık
                    if tcp_all_done.is_set() and deep_q.empty():
                        break
                    continue
                if item is None:
                    break  # Sentinel
                if should_stop.is_set() or self._stop_fill.is_set():
                    continue
                ip, port, ping = item
                self.in_progress[ip] = time.monotonic()
                try:
                    verified = await self._deep_verify(ip, port, ping)
                    if not verified:
                        self._mark_bad(ip)
                except asyncio.CancelledError:
                    break
                except Exception:
                    pass
                finally:
                    self.in_progress.pop(ip, None)

        # ----------------------------------------------------------------
        prod_task = asyncio.create_task(producer())
        tcp_tasks = [
            asyncio.create_task(tcp_worker()) for _ in range(self.num_workers)
        ]
        sentinel_task = asyncio.create_task(deep_sentinel_sender())
        deep_tasks = [
            asyncio.create_task(deep_worker()) for _ in range(self.deep_concurrency)
        ]

        self._tasks = [prod_task, sentinel_task] + tcp_tasks + deep_tasks

        await asyncio.gather(*self._tasks, return_exceptions=True)

        self._save_results()
        if self.bad_cache:
            self.bad_cache.flush()
        self.finished.set()
        return self.results
