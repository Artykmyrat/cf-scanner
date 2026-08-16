"""
cf_scanner.ui
==============
Rich tabanlı, ekrana sığan, animasyonlu canlı dashboard.

Tasarım ilkesi: Tarama mantığı (scanner.py) bu modülden tamamen bağımsızdır.
Scanner nesnesinin durumu her 100-150 ms'de bir okunup yeniden çizilir.
"""
from __future__ import annotations

import asyncio
import time
from typing import Optional

from rich.console import Console, Group
from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.table import Table
from rich.text import Text

from .models import ProxyConfig
from .scanner import Scanner

_SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

MODE_LABEL = {
    "cloudflare": "Cloudflare Tespiti",
    "raw": "TLS Testi (Xray-Core kapalı)",
    "xray": "Xray-Core Tam Tünel (%100 emin)",
}


def _spin() -> str:
    return _SPINNER[int(time.monotonic() * 7) % len(_SPINNER)]


def _fmt_eta(s: Optional[float]) -> str:
    if s is None:
        return "--:--"
    s = int(s)
    m, ss = divmod(s, 60)
    h, m = divmod(m, 60)
    return f"{h}:{m:02d}:{ss:02d}" if h else f"{m:02d}:{ss:02d}"


def _stat_panel(scanner: Scanner, asn: str, mode: str,
                cfg: Optional[ProxyConfig], xray_active: bool) -> Panel:
    st = scanner.stats
    stopped = scanner.stop_requested
    spin = _spin()
    state_txt = "[red]DURDURULUYOR[/]" if stopped else "[cyan]TARANIYOR[/]"

    pct = (st.scanned / st.total * 100) if st.total else 0.0
    bar = ProgressBar(total=max(st.total, 1), completed=min(st.scanned, st.total))

    # Üst satır: durum + hız + süre
    top = Text()
    top.append(f"{spin} ", style="cyan")
    top.append(state_txt + "  ")
    top.append(f"{st.scanned:,}/{st.total:,}  ({pct:.1f}%)", style="bold")
    top.append(f"   {st.speed:.0f} ip/s   {int(st.elapsed)}s   kalan: {_fmt_eta(st.eta_seconds)}", style="dim")

    # Orta satır: hedef + mod + config
    mid = Table.grid(padding=(0, 2))
    mid.add_column(style="dim")
    mid.add_column()
    mid.add_row("Hedef:", asn or "-")
    mid.add_row("Mod:", MODE_LABEL.get(mode, mode))
    if cfg:
        mid.add_row("Config:", f"{cfg.name}  [{cfg.short_desc()}]")
    mid.add_row("Xray-Core:", "[green]aktif[/]" if xray_active else "[yellow]kapalı[/]")

    # Alt satır: sayaçlar
    bot = Text()
    bot.append(f"canlı port: {st.alive:,}   ", style="dim")
    bot.append(f"✓ doğrulanan: {st.verified:,}", style="bold green")
    if st.skipped_known_bad:
        bot.append(f"   geçersiz(önbellek): {st.skipped_known_bad:,}", style="dim")
    if st.skipped_resumed:
        bot.append(f"   atlandı(önceki): {st.skipped_resumed:,}", style="dim")

    return Panel(
        Group(top, bar, Text(""), mid, Text(""), bot),
        border_style="cyan",
        padding=(0, 2),
    )


def _inprogress_panel(scanner: Scanner) -> Optional[Panel]:
    """Derin doğrulama aşamasındaki IP'leri gösterir."""
    now = time.monotonic()
    ips = list(scanner.in_progress.items())
    if not ips:
        return None

    tbl = Table(show_header=True, header_style="dim", border_style="dim",
                show_lines=False, expand=True)
    tbl.add_column("Test edilen IP", style="cyan", no_wrap=True)
    tbl.add_column("Süre", justify="right", style="dim")

    # En uzun bekleyenden başla
    for ip, start in sorted(ips, key=lambda x: x[1])[:10]:
        elapsed_ms = int((now - start) * 1000)
        tbl.add_row(ip, f"{elapsed_ms} ms")

    return Panel(tbl, title=f"Şu an test ediliyor ({len(ips)})", title_align="left",
                 border_style="yellow")


def _results_panel(scanner: Scanner, max_rows: int) -> Panel:
    tbl = Table(show_header=True, header_style="dim", border_style="dim",
                show_lines=False, expand=True)
    tbl.add_column("IP", style="bold", no_wrap=True)
    tbl.add_column("Port", justify="right")
    tbl.add_column("Ping", justify="right")
    tbl.add_column("Yöntem", style="dim")
    tbl.add_column("Tünel ms", justify="right")
    tbl.add_column("Zaman", style="dim")

    rows = scanner.results[-max_rows:][::-1]
    for r in rows:
        t = time.strftime("%H:%M:%S", time.localtime(r.checked_at))
        tun = str(r.tunnel_latency_ms) if r.tunnel_latency_ms is not None else "-"
        tbl.add_row(r.ip, str(r.verified_port or "-"), f"{r.ping_ms}ms",
                    r.verify_method, tun, t)

    if not rows:
        tbl.add_row("[dim]henüz doğrulanmış IP yok...[/dim]", "", "", "", "", "")

    title = f"[green]Doğrulanan IP'ler[/]  (toplam: {len(scanner.results)}, son {max_rows} gösteriliyor)"
    return Panel(tbl, title=title, title_align="left", border_style="green")


def render(scanner: Scanner, asn: str, mode: str,
           cfg: Optional[ProxyConfig], xray_active: bool,
           result_path: str, console: Console) -> Group:
    height = console.size.height
    # Derin doğrulama varsa yer bırak
    has_progress = bool(scanner.in_progress)
    result_rows = max(4, min(12, height - (22 if has_progress else 16)))

    parts = [_stat_panel(scanner, asn, mode, cfg, xray_active)]

    ip_panel = _inprogress_panel(scanner)
    if ip_panel is not None:
        parts.append(ip_panel)

    parts.append(_results_panel(scanner, result_rows))
    parts.append(Text(
        f"Ctrl+C: hemen durdur  •  sonuçlar anlık kaydediliyor → {result_path}",
        style="dim",
    ))
    return Group(*parts)


async def run_dashboard(scanner: Scanner, asn: str, mode: str,
                         cfg: Optional[ProxyConfig], xray_active: bool,
                         result_path: str) -> None:
    from rich.live import Live
    console = Console()
    with Live(console=console, refresh_per_second=7, screen=False) as live:
        while not scanner.finished.is_set():
            live.update(render(scanner, asn, mode, cfg, xray_active, result_path, console))
            try:
                await asyncio.wait_for(scanner.finished.wait(), timeout=0.13)
            except asyncio.TimeoutError:
                pass
        live.update(render(scanner, asn, mode, cfg, xray_active, result_path, console))


def print_summary(scanner: Scanner, result_path: str) -> None:
    console = Console()
    st = scanner.stats
    tbl = Table.grid(padding=(0, 2))
    tbl.add_column(style="bold")
    tbl.add_column()
    tbl.add_row("Taranan IP:", f"{st.scanned:,}")
    tbl.add_row("Canlı port bulunan:", f"{st.alive:,}")
    tbl.add_row("Doğrulanan:", f"[bold green]{st.verified:,}[/]")
    if st.skipped_known_bad:
        tbl.add_row("Atlanan (önbellek):", f"{st.skipped_known_bad:,}")
    if st.skipped_resumed:
        tbl.add_row("Atlanan (önceki sonuç):", f"{st.skipped_resumed:,}")
    tbl.add_row("Toplam süre:", f"{int(st.elapsed)} sn  ({st.speed:.0f} ip/s)")
    tbl.add_row("Sonuç dosyası:", result_path)
    console.print(Panel(tbl, title="Tarama Özeti", border_style="cyan"))
