"""
cf_scanner.xray_manager
=========================
Xray-core ikili dosyasını indirir/yönetir, her protokol için doğru JSON
config'i üretir (fragment / REALITY / gRPC / xHTTP / WS dahil) ve adayı
GERÇEK bir VLESS/VMess/Trojan/SS tüneli üzerinden internete çıkararak
"100% emin" doğrulama yapar.

ÖNEMLİ (Haziran 2026 itibarıyla doğrulanmış güncel bilgi):
  Xray-core'da "allowInsecure" alanı 2026-06-01'den itibaren TAMAMEN
  KALDIRILDI (artık config parse hatası verip süreci başlatmıyor).
  Bu modül bu alanı HİÇ üretmez. SNI doğru girildiğinde Cloudflare zaten
  geçerli bir sertifika sunduğu için normal CA doğrulaması sorunsuz çalışır.
  Linkte pcs (pinnedPeerCertSha256) / vcn (verifyPeerCertByName) varsa onlar
  kullanılır.

Bu modül tamamen YALITILMIŞTIR: kaldırmak istenirse sadece bu dosyayı silmek
ve scanner.py / main.py içindeki xray importlarını/menü seçeneklerini
kapatmak yeterlidir (bkz. README "Xray-core'u kaldırmak istiyorum").
"""
from __future__ import annotations

import asyncio
import json
import os
import platform
import shutil
import stat
import tempfile
import time
import zipfile
from dataclasses import dataclass
from typing import Optional, List, Dict, Any, Tuple

import requests
import aiohttp
from aiohttp_socks import ProxyConnector

from .models import ProxyConfig
from .checks import tcp_ping

GITHUB_LATEST_API = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
GITHUB_RELEASES_PAGE = "https://github.com/XTLS/Xray-core/releases/latest"

# İnternete çıkış doğrulaması için kullanılan hafif/güvenilir hedefler.
# Birden fazla hedef olması tek bir hedefin geçici olarak engellenmiş
# olmasına karşı dayanıklılık sağlar ("herşeye hazır olsun").
VERIFY_TARGETS = [
    "http://www.gstatic.com/generate_204",
    "http://cp.cloudflare.com/generate_204",
    "http://detectportal.firefox.com/success.txt",
]

USER_AGENT = "cf-scanner-tool/1.0 (+https://github.com/XTLS/Xray-core)"


def _bin_dir() -> str:
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin")
    os.makedirs(d, exist_ok=True)
    return os.path.abspath(d)


def _binary_path() -> str:
    name = "xray.exe" if platform.system() == "Windows" else "xray"
    return os.path.join(_bin_dir(), name)


def _is_termux() -> bool:
    """Termux ortamını güvenilir şekilde tespit eder.
    Termux her zaman PREFIX=/data/data/com.termux/files/usr ortam değişkenini
    set eder; ek olarak Android'e özgü ANDROID_ROOT/ANDROID_DATA da kontrol edilir."""
    prefix = os.environ.get("PREFIX", "")
    if "com.termux" in prefix:
        return True
    if os.environ.get("TERMUX_VERSION"):
        return True
    if os.environ.get("ANDROID_ROOT") or os.environ.get("ANDROID_DATA"):
        return True
    return False


def _detect_asset_tokens() -> Tuple[str, str]:
    """Bu makineye uygun Xray-core release asset adındaki (platform, arch)
    token'larını döner. Örn: ('linux', '64'), ('android', 'arm64-v8a').

    ÖNEMLİ: Termux, çekirdek olarak Linux kullandığı için platform.system()
    'Linux' döner — ama Xray-core'un normal 'linux-*' derlemeleri glibc
    varsayımıyla derlenir ve Android'in bionic libc'siyle UYUMSUZ olabilir.
    Bu yüzden Xray-core projesi Android için AYRI bir derleme seti yayınlıyor
    ("Xray-android-arm64-v8a.zip" / "Xray-android-amd64.zip"). Termux tespit
    edildiğinde bilerek 'android' asset'i seçilir.
    """
    system = platform.system()
    machine = platform.machine().lower()

    if _is_termux():
        plat = "android"
    elif system == "Linux":
        plat = "linux"
    elif system == "Darwin":
        plat = "macos"
    elif system == "Windows":
        plat = "windows"
    else:
        raise RuntimeError(f"Desteklenmeyen işletim sistemi: {system}")

    if plat == "android":
        # Xray-core Android için sadece 2 mimari yayınlıyor: arm64-v8a ve amd64
        if machine in ("aarch64", "arm64"):
            arch = "arm64-v8a"
        elif machine in ("x86_64", "amd64"):
            arch = "amd64"
        else:
            # Eski 32-bit ARM telefonlar için Android derlemesi yok;
            # en yakın seçenek olarak linux-arm32-v7a'ya düşülür (manuel kontrol önerilir).
            plat = "linux"
            arch = "arm32-v7a"
        return plat, arch

    if machine in ("x86_64", "amd64"):
        arch = "64"
    elif machine in ("i386", "i686", "x86"):
        arch = "32"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64-v8a"
    elif machine.startswith("armv7") or machine == "armv7l":
        arch = "arm32-v7a"
    else:
        # Bilinmeyen mimari için en yaygın olana düş (kullanıcı manuel indirip
        # bin/ klasörüne koyabilir, README'de açıklanıyor)
        arch = "64"
    return plat, arch


def get_manual_download_info() -> Dict[str, str]:
    """Kullanıcıya gösterilecek indirme bilgisi: resmi release sayfası +
    bu makine için beklenen dosya adı."""
    try:
        plat, arch = _detect_asset_tokens()
        expected = f"Xray-{plat}-{arch}.zip"
    except RuntimeError:
        expected = "Xray-<platform>-<arch>.zip"
    return {
        "releases_page": GITHUB_RELEASES_PAGE,
        "expected_asset": expected,
        "bin_dir": _bin_dir(),
    }


class XrayDownloadError(RuntimeError):
    pass


def download_latest_xray(progress_cb=None) -> str:
    """En son Xray-core sürümünü GitHub Releases'tan indirir, bin/ klasörüne
    çıkarır ve çalıştırılabilir hale getirir. Yol döner.

    progress_cb(stage:str, detail:str) -> None  (opsiyonel, UI için)
    """
    def report(stage, detail=""):
        if progress_cb:
            progress_cb(stage, detail)

    plat, arch = _detect_asset_tokens()
    report("api", "GitHub release bilgisi alınıyor...")

    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    try:
        r = requests.get(GITHUB_LATEST_API, headers=headers, timeout=20)
        r.raise_for_status()
        data = r.json()
    except requests.RequestException as e:
        raise XrayDownloadError(
            f"GitHub API'ye erişilemedi ({e}). Eğer Türkmenistan'dan GitHub "
            f"erişimi kısıtlıysa, mevcut bir VPN/proxy üzerinden tekrar deneyin "
            f"veya {GITHUB_RELEASES_PAGE} adresinden manuel indirin."
        )

    assets = data.get("assets", [])
    if not assets:
        raise XrayDownloadError("Release asset listesi boş döndü (rate limit olabilir, biraz sonra tekrar deneyin).")

    wanted_name = f"xray-{plat}-{arch}".lower()
    candidate = None
    for a in assets:
        name = a.get("name", "")
        nlow = name.lower()
        if nlow.endswith(".zip") and plat in nlow and arch in nlow:
            candidate = a
            break
    if candidate is None:
        # daha gevşek eşleştirme: sadece platform + '64' ara
        for a in assets:
            nlow = a.get("name", "").lower()
            if nlow.endswith(".zip") and plat in nlow:
                candidate = a
                break
    if candidate is None:
        names = ", ".join(a.get("name", "?") for a in assets)
        raise XrayDownloadError(
            f"Bu sistem için uygun Xray-core dosyası bulunamadı (aranan: {wanted_name}). "
            f"Mevcut dosyalar: {names}"
        )

    download_url = candidate["browser_download_url"]
    report("download", f"{candidate['name']} indiriliyor...")

    bin_dir = _bin_dir()
    tmp_zip = os.path.join(bin_dir, "_xray_download.zip")
    try:
        with requests.get(download_url, headers={"User-Agent": USER_AGENT}, stream=True, timeout=120) as resp:
            resp.raise_for_status()
            with open(tmp_zip, "wb") as f:
                for chunk in resp.iter_content(chunk_size=1 << 16):
                    if chunk:
                        f.write(chunk)
    except requests.RequestException as e:
        raise XrayDownloadError(f"İndirme başarısız: {e}")

    report("extract", "Arşivden çıkarılıyor...")
    try:
        with zipfile.ZipFile(tmp_zip, "r") as zf:
            zf.extractall(bin_dir)
    finally:
        try:
            os.remove(tmp_zip)
        except OSError:
            pass

    bin_path = _binary_path()
    if not os.path.exists(bin_path):
        # Bazı sürümlerde dosya adı 'xray' değil farklı olabilir; klasördeki
        # ilk çalıştırılabilir adayı bul.
        for fn in os.listdir(bin_dir):
            if fn.lower() in ("xray", "xray.exe"):
                bin_path = os.path.join(bin_dir, fn)
                break

    if not os.path.exists(bin_path):
        raise XrayDownloadError("Arşiv açıldı ama xray çalıştırılabilir dosyası bulunamadı.")

    if platform.system() != "Windows":
        st = os.stat(bin_path)
        os.chmod(bin_path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    report("done", bin_path)
    return bin_path


def find_existing_binary() -> Optional[str]:
    p = _binary_path()
    if platform.system() == "Windows":
        if os.path.exists(p):
            return p
    else:
        if os.path.exists(p) and os.access(p, os.X_OK):
            return p
    # PATH üzerinde sistem genelinde kurulu bir xray var mı?
    system_xray = shutil.which("xray")
    if system_xray:
        return system_xray
    return None


# ---------------------------------------------------------------------------
# Config (JSON) üretimi
# ---------------------------------------------------------------------------

def _tls_block(cfg: ProxyConfig) -> Dict[str, Any]:
    block: Dict[str, Any] = {
        "serverName": cfg.sni or cfg.address,
    }
    # ÖNEMLİ DÜZELTME: ALPN'i SADECE link'te hiç belirtilmemişse
    # varsayılan olarak dolduruyoruz. ESKİDEN link'teki ALPN ne olursa olsun
    # (örn. alpn=h3) buraya zorla "h2" ekleniyordu — bu, XHTTP'nin gerçek
    # QUIC/H3 moduna geçmesini TAMAMEN engelliyordu: Xray-core'un kendi
    # belgelerine göre (XTLS/Xray-core discussion #4113) XHTTP sadece ALPN
    # TAM OLARAK ["h3"] ise (başka hiçbir eleman olmadan) quic-go ile gerçek
    # UDP/QUIC bağlantısına geçiyor; listede "h2" de varsa sessizce normal
    # TCP+HTTP/2'ye düşüyor. Yani kullanıcının fp/alpn=h3 içeren configleri
    # önceden fiilen hiçbir zaman gerçek H3/QUIC kullanmıyordu.
    alpn: List[str] = list(cfg.alpn) if cfg.alpn else []
    if not alpn and cfg.network in ("grpc", "xhttp"):
        alpn = ["h2"]
    if alpn:
        block["alpn"] = alpn
    if cfg.fingerprint:
        block["fingerprint"] = cfg.fingerprint
    # allowInsecure KASITLI OLARAK eklenmiyor — Xray-Core 2026-06-01'den itibaren kaldırdı.
    if cfg.pinned_cert_sha256:
        block["pinnedPeerCertSha256"] = cfg.pinned_cert_sha256
    if cfg.verify_peer_cert_by_name:
        block["verifyPeerCertByName"] = cfg.verify_peer_cert_by_name
    return block


def _reality_block(cfg: ProxyConfig) -> Dict[str, Any]:
    return {
        "serverName": cfg.sni or cfg.address,
        "fingerprint": cfg.fingerprint or "chrome",
        "publicKey": cfg.reality_public_key,
        "shortId": cfg.reality_short_id,
        "spiderX": cfg.reality_spider_x or "",
    }


def _stream_settings(cfg: ProxyConfig, ip: str, fragment_tag: Optional[str]) -> Dict[str, Any]:
    ss: Dict[str, Any] = {"network": cfg.network}

    if cfg.network == "ws":
        ws: Dict[str, Any] = {"path": cfg.path or "/"}
        # WS Host başlığı: link'teki host → yoksa SNI. CDN yönlendirmesi için zorunlu.
        # DÜZELTME: headers.Host yerine doğrudan 'host' alanı kullanılıyor.
        # Xray-core artık headers üzerinden Host ayarlamayı KULLANIMDAN
        # KALDIRILACAK olarak işaretledi ("deprecated ... before removal");
        # dedicated 'host' alanı güncel/önerilen yöntemdir.
        host_header = cfg.host or cfg.sni
        if host_header:
            ws["host"] = host_header
        ss["wsSettings"] = ws

    elif cfg.network == "grpc":
        ss["grpcSettings"] = {
            "serviceName": cfg.service_name or cfg.path,
            "multiMode": (cfg.grpc_mode == "multi"),
            # authority: HTTP/2 :authority pseudo-header. Boş bırakmak güvenli
            # (Xray-Core TLS serverName'den alır). Ama açıkça ayarlanmışsa kullan.
            "authority": cfg.host or "",
        }

    elif cfg.network == "xhttp":
        # KRİTİK DÜZELTME: xHTTP'de HTTP Host başlığı her zaman ayarlanmalı.
        # host boşsa Cloudflare CDN hangi origin'e yönlendireceğini bilemez
        # ve 400 Bad Request / 421 Misdirected Request döner.
        # Bu, xHTTP için false negative'lerin ana nedenidir.
        xhttp_host = cfg.host or cfg.sni or cfg.address
        xh: Dict[str, Any] = {
            "path": cfg.path or "/",
            "mode": cfg.xhttp_mode or "auto",
            "host": xhttp_host,
        }
        # DÜZELTME: linkteki 'extra' parametresi (padding/xmux/scMax* vb.)
        # önceden HİÇ okunmuyor ve build edilen confige hiç yansımıyordu.
        # link_parser zaten sayısal tipleri (1000000.0 -> 1000000) temizleyip
        # veriyor (bkz. link_parser._sanitize_json_numbers) — Xray-core'un
        # Go JSON çözümleyicisi float alırsa configin TAMAMEN başlamamasına
        # neden oluyordu, bu yüzden ham veriyi burada tekrar işlemiyoruz.
        if cfg.xhttp_extra:
            xh["extra"] = cfg.xhttp_extra
        ss["xhttpSettings"] = xh

    # network == "tcp" → ek ayar gerekmez

    if cfg.security == "tls":
        ss["security"] = "tls"
        ss["tlsSettings"] = _tls_block(cfg)
    elif cfg.security == "reality":
        ss["security"] = "reality"
        ss["realitySettings"] = _reality_block(cfg)
    else:
        ss["security"] = "none"

    if fragment_tag:
        ss["sockopt"] = {"dialerProxy": fragment_tag}

    return ss


def build_outbounds(cfg: ProxyConfig, ip: str) -> List[Dict[str, Any]]:
    """Ana proxy outbound'u (+ varsa fragment/Finalmask freedom outbound'u) üretir."""
    outbounds: List[Dict[str, Any]] = []
    fragment_tag = "fragment-out" if cfg.fragment else None

    if cfg.protocol == "vless":
        user: Dict[str, Any] = {"id": cfg.uid, "encryption": cfg.encryption or "none"}
        # DÜZELTME: flow (xtls-rprx-vision vb.) SADECE raw tcp + tls/reality
        # ile geçerlidir. ws/grpc/xhttp ile birlikte gelirse Xray-core config'i
        # sorunsuz PARSE EDER ama gerçek bağlantı aşamasında sessizce
        # başarısız olur (config-test bunu yakalamaz, sadece gerçek tünel
        # denemesi ortaya çıkarır) — bu yüzden burada baştan eleniyor.
        if cfg.flow and cfg.network == "tcp" and cfg.security in ("tls", "reality"):
            user["flow"] = cfg.flow
        settings = {"vnext": [{"address": ip, "port": cfg.port, "users": [user]}]}
        proto = "vless"
    elif cfg.protocol == "vmess":
        user = {"id": cfg.uid, "alterId": cfg.alter_id, "security": cfg.vmess_security or "auto"}
        settings = {"vnext": [{"address": ip, "port": cfg.port, "users": [user]}]}
        proto = "vmess"
    elif cfg.protocol == "trojan":
        settings = {"servers": [{"address": ip, "port": cfg.port, "password": cfg.password}]}
        proto = "trojan"
    elif cfg.protocol == "shadowsocks":
        settings = {"servers": [{"address": ip, "port": cfg.port, "method": cfg.method, "password": cfg.password}]}
        proto = "shadowsocks"
    else:
        raise ValueError(f"Desteklenmeyen protokol: {cfg.protocol}")

    main_outbound: Dict[str, Any] = {
        "tag": "proxy",
        "protocol": proto,
        "settings": settings,
    }
    if proto != "shadowsocks" or cfg.network != "tcp" or cfg.security != "none":
        main_outbound["streamSettings"] = _stream_settings(cfg, ip, fragment_tag)

    outbounds.append(main_outbound)

    if cfg.fragment:
        outbounds.append({
            "tag": fragment_tag,
            "protocol": "freedom",
            "settings": {
                "fragment": {
                    "packets": cfg.fragment.get("packets", "tlshello"),
                    "length": cfg.fragment.get("length", "100-200"),
                    "interval": cfg.fragment.get("interval", "10-20"),
                }
            },
        })

    outbounds.append({"tag": "direct", "protocol": "freedom"})
    return outbounds


def build_full_config(cfg: ProxyConfig, ip: str, socks_port: int) -> Dict[str, Any]:
    return {
        "log": {"loglevel": "none"},
        "inbounds": [
            {
                "tag": "in-socks",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }
        ],
        "outbounds": build_outbounds(cfg, ip),
    }


# ---------------------------------------------------------------------------
# Port havuzu
# ---------------------------------------------------------------------------

class PortPool:
    def __init__(self, start: int = 31000, size: int = 200):
        self._free = asyncio.Queue()
        for p in range(start, start + size):
            self._free.put_nowait(p)

    async def acquire(self) -> int:
        return await self._free.get()

    def release(self, port: int) -> None:
        self._free.put_nowait(port)


# ---------------------------------------------------------------------------
# Gerçek tünel testi
# ---------------------------------------------------------------------------

@dataclass
class TunnelTestResult:
    success: bool
    latency_ms: Optional[int] = None
    error: str = ""


# Transport türüne göre (startup_timeout, request_timeout) saniye cinsinden.
# xHTTP: TLS + HTTP/2 upgrade + xHTTP tünel kurulumu üç aşamalı → daha uzun süre.
# gRPC/WS: iki aşamalı → orta.
# TCP/SS: tek aşamalı → kısa.
_TRANSPORT_TIMEOUTS: Dict[str, Tuple[float, float]] = {
    "xhttp":      (7.0, 18.0),   # En yavaş: HTTP/2 upgrade + xHTTP
    "grpc":       (5.0, 12.0),   # gRPC HTTP/2
    "ws":         (5.0, 12.0),   # WebSocket upgrade
    "tcp":        (4.0,  9.0),   # Direkt TLS
    "shadowsocks":(3.0,  8.0),   # SS (transport katmanı yok)
}


class XrayCoreManager:
    def __init__(
        self,
        binary_path: Optional[str] = None,
        port_pool: Optional[PortPool] = None,
        max_concurrent: int = 25,
    ):
        self.binary_path = binary_path or find_existing_binary()
        self.port_pool = port_pool or PortPool()
        self._sem = asyncio.Semaphore(max_concurrent)
        self._tmp_dir = tempfile.mkdtemp(prefix="cfscan_xray_")

    @property
    def available(self) -> bool:
        return bool(self.binary_path and os.path.exists(self.binary_path))

    def cleanup(self) -> None:
        shutil.rmtree(self._tmp_dir, ignore_errors=True)

    def _timeouts(self, network: str) -> Tuple[float, float]:
        """(startup_timeout, request_timeout) — transport türüne göre."""
        return _TRANSPORT_TIMEOUTS.get(network, (5.0, 12.0))

    async def verify(self, cfg: ProxyConfig, ip: str) -> TunnelTestResult:
        """Adayı gerçek bir tünel açıp internete çıkararak doğrular (%100 emin).
        UUID/şifre + sunucunun trafiği gerçekten geçirebilmesi test edilir."""
        if not self.available:
            return TunnelTestResult(False, error="xray-core bulunamadı")

        startup_timeout, request_timeout = self._timeouts(cfg.network)

        async with self._sem:
            port = await self.port_pool.acquire()
            cfg_path = os.path.join(
                self._tmp_dir, f"{ip.replace('.', '_')}_{port}.json"
            )
            proc = None
            try:
                full_cfg = build_full_config(cfg, ip, port)
                with open(cfg_path, "w", encoding="utf-8") as f:
                    json.dump(full_cfg, f)

                proc = await asyncio.create_subprocess_exec(
                    self.binary_path, "run", "-c", cfg_path,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )

                ready = await self._wait_ready(port, startup_timeout)
                if not ready:
                    return TunnelTestResult(
                        False,
                        error=f"xray-core başlatılamadı (timeout={startup_timeout}s)"
                    )

                return await self._http_through_socks(port, request_timeout)

            except asyncio.CancelledError:
                raise
            except Exception as e:
                return TunnelTestResult(False, error=str(e))
            finally:
                if proc is not None and proc.returncode is None:
                    try:
                        proc.terminate()
                        await asyncio.wait_for(proc.wait(), timeout=2.0)
                    except (asyncio.TimeoutError, ProcessLookupError):
                        try:
                            proc.kill()
                        except ProcessLookupError:
                            pass
                try:
                    os.remove(cfg_path)
                except OSError:
                    pass
                self.port_pool.release(port)

    async def _wait_ready(self, port: int, startup_timeout: float) -> bool:
        deadline = time.monotonic() + startup_timeout
        while time.monotonic() < deadline:
            if await tcp_ping("127.0.0.1", port, timeout=0.3) is not None:
                return True
            await asyncio.sleep(0.06)
        return False

    async def _http_through_socks(
        self, socks_port: int, request_timeout: float
    ) -> TunnelTestResult:
        connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{socks_port}")
        last_error = ""
        for target in VERIFY_TARGETS:
            start = time.monotonic()
            try:
                async with aiohttp.ClientSession(
                    connector=connector, connector_owner=False
                ) as session:
                    async with session.get(
                        target,
                        timeout=aiohttp.ClientTimeout(total=request_timeout),
                        allow_redirects=True,
                    ) as resp:
                        if resp.status < 400:
                            latency = int((time.monotonic() - start) * 1000)
                            await connector.close()
                            return TunnelTestResult(True, latency_ms=latency)
                        last_error = f"HTTP {resp.status}"
            except asyncio.CancelledError:
                await connector.close()
                raise
            except Exception as e:
                last_error = str(e)
        await connector.close()
        return TunnelTestResult(
            False,
            error=last_error or "tünel üzerinden hiçbir hedefe ulaşılamadı",
        )
