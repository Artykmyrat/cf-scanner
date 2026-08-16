#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CF-Scanner Pro
==============
scan.go'nun eksiksiz Python karşılığı + Xray-Core ile %100 emin tünel
doğrulama + VLESS/VMess/Trojan/Shadowsocks için tam protokol desteği
(tcp/ws/grpc/xhttp, tls/reality, fragment/Finalmask) + bilinen-geçersiz IP
hafızası (30 gün) + ekrana sığan, sakin/animasyonlu rich arayüzü.

Kullanım:
    python3 main.py                           # İnteraktif mod
    python3 main.py --scan xray --asn AS13335  # CLI ile
    python3 main.py --init-config              # config.toml oluştur
    python3 main.py --show-config              # mevcut ayarları göster
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import signal
import sys
from typing import List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table

from cf_scanner import ripe, ui
from cf_scanner.cache_store import BadIPCache
from cf_scanner.config import load_config, create_default_config, show_config, AppConfig
from cf_scanner.config_store import ConfigStore
from cf_scanner.link_parser import parse_link
from cf_scanner.models import ProxyConfig
from cf_scanner.scanner import Scanner, load_existing_results
from cf_scanner.xray_manager import (
    XrayCoreManager, find_existing_binary, download_latest_xray,
    get_manual_download_info, XrayDownloadError,
)

console = Console()

DEFAULT_CF_PORTS = [443, 2053, 2083, 2087, 2096, 8443, 8880, 2052, 2082, 2086, 80]


# ============================================================================
# Genel yardımcılar
# ============================================================================

def banner() -> None:
    console.clear()
    console.print(Panel.fit(
        "[bold cyan]CF-Scanner Pro[/]\n"
        "[dim]Cloudflare Edge IP Tarayıcı  •  Xray-Core Tam Tünel Doğrulama\n"
        "VLESS · VMess · Trojan · Shadowsocks  |  WS / gRPC / xHTTP  |  TLS / REALITY / Fragment[/]",
        border_style="cyan",
    ))


def pause() -> None:
    Prompt.ask("\n[dim]Devam etmek için Enter'a basın[/]", default="", show_default=False)


def slugify(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    return text.strip("_") or "config"


def make_context_key(mode: str, cfg: Optional[ProxyConfig], ports: List[int]) -> str:
    port_part = ",".join(str(p) for p in sorted(ports))
    if cfg is not None:
        return f"{mode}:{cfg.id}:{port_part}"
    return f"{mode}:{port_part}"


def default_result_path(mode: str, cfg: Optional[ProxyConfig]) -> str:
    import os
    os.makedirs("results", exist_ok=True)
    name = slugify(cfg.name) if cfg is not None else "cloudflare"
    return os.path.join("results", f"{mode}_{name}.json")


def make_unique_path(path: str) -> str:
    import os
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    i = 2
    while os.path.exists(f"{base}_{i}{ext}"):
        i += 1
    return f"{base}_{i}{ext}"


def parse_port_list(raw: str, default: List[int]) -> List[int]:
    raw = raw.strip()
    if not raw:
        return default
    out = []
    for p in raw.split(","):
        p = p.strip()
        if p.isdigit():
            out.append(int(p))
    return out or default


def parse_manual_cidrs(raw: str) -> List[ipaddress.IPv4Network]:
    nets = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            if "/" in token:
                nets.append(ipaddress.ip_network(token, strict=False))
            else:
                nets.append(ipaddress.ip_network(token + "/32", strict=False))
        except ValueError:
            console.print(f"[red]Geçersiz IP/CIDR atlandı:[/] {token}")
    return nets


def run_with_dashboard(scanner: Scanner, asn: str, mode: str, cfg: Optional[ProxyConfig],
                        xray_active: bool, result_path: str) -> None:
    async def _main():
        await asyncio.gather(
            scanner.run(),
            ui.run_dashboard(scanner, asn, mode, cfg, xray_active, result_path),
        )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        try:
            loop.add_signal_handler(signal.SIGINT, scanner.request_stop)
        except (NotImplementedError, RuntimeError, AttributeError):
            pass
        loop.run_until_complete(_main())
    except KeyboardInterrupt:
        scanner.request_stop()
        try:
            loop.run_until_complete(asyncio.wait_for(scanner.finished.wait(), timeout=5))
        except Exception:
            pass
    finally:
        try:
            scanner._save_results()
        except Exception:
            pass
        if scanner.bad_cache:
            try:
                scanner.bad_cache.flush()
            except Exception:
                pass
        loop.close()

    ui.print_summary(scanner, result_path)


# ============================================================================
# Hedef seçimi: ASN ve/veya elle CIDR/IP — BİRLİKTE kullanılabilir
# ============================================================================

def pick_targets_combined() -> Tuple[Optional[str], Optional[List[ipaddress.IPv4Network]], Optional[int]]:
    console.print("\n[bold]Hedefler[/] [dim](en az birini doldurun — ikisini birlikte de kullanabilirsiniz)[/]")
    asn = Prompt.ask("ASN (örn. AS13335 = Cloudflare) — atlamak için boş geçin", default="")
    manual_raw = Prompt.ask("Ek CIDR/IP listesi, virgülle ayırın (örn. 188.114.96.0/24, 1.1.1.1) — atlamak için boş geçin",
                             default="")

    networks: List[ipaddress.IPv4Network] = []
    label_parts: List[str] = []

    asn = asn.strip()
    if asn:
        console.print(f"[dim]RIPEstat'tan {asn} prefixleri çekiliyor...[/]")
        try:
            prefixes = asyncio.run(ripe.fetch_prefixes(asn))
        except Exception as e:
            console.print(f"[red]RIPE'tan veri alınamadı:[/] {e}")
            prefixes = []
        if prefixes:
            asn_networks = ripe.split_to_24(prefixes)
            networks.extend(asn_networks)
            label_parts.append(asn.upper())
            console.print(f"[green]{asn.upper()}: {len(prefixes)} prefix → {len(asn_networks)} /24 blok[/]")
        else:
            console.print(f"[yellow]{asn.upper()} için prefix bulunamadı, atlanıyor.[/]")

    manual_raw = manual_raw.strip()
    if manual_raw:
        manual_networks = parse_manual_cidrs(manual_raw)
        if manual_networks:
            networks.extend(manual_networks)
            label_parts.append(f"{len(manual_networks)} elle girilen blok")

    if not networks:
        console.print("[red]Hiçbir geçerli hedef girilmedi, tarama başlatılamıyor.[/]")
        return None, None, None

    # Aynı bloğun iki kaynaktan birden gelip tekrar taranmasını önle
    seen = set()
    deduped = []
    for n in networks:
        if n not in seen:
            seen.add(n)
            deduped.append(n)

    total = sum(n.num_addresses for n in deduped)
    label = " + ".join(label_parts)
    console.print(f"[green]Toplam {len(deduped)} blok, {total:,} IP taranacak.[/]")
    return label, deduped, total


# ============================================================================
# Sonuç dosyası: devam et / yeni başlat
# ============================================================================

def resolve_result_path(result_path: str):
    existing = load_existing_results(result_path)
    if existing:
        console.print(f"\n[yellow]'{result_path}' dosyasında zaten {len(existing)} doğrulanmış IP var.[/]")
        choice = Prompt.ask("Bu kayıtların üzerine devam edilsin mi (eskiler atlanır, tekrar test edilmez) "
                             "yoksa yeni bir dosyaya mı başlansın?",
                             choices=["devam", "yeni"], default="devam")
        if choice == "yeni":
            new_path = make_unique_path(result_path)
            console.print(f"[dim]Yeni dosya: {new_path}[/]")
            return new_path, []
    return result_path, existing


# ============================================================================
# Tarama Sihirbazı (tek ekrandan: tür + config + hedef + ayarlar)
# ============================================================================

def menu_start_scan(store: ConfigStore, xray_holder: dict, bad_cache: BadIPCache,
                    app_config: AppConfig) -> None:
    banner()
    console.print("[bold]Tarama Türü[/]")
    console.print("  1) Sade Cloudflare tespiti (config gerekmez, sadece IP'nin Cloudflare arkasında olup olmadığına bakar)")
    console.print("  2) Config ile doğrulama (VLESS/VMess/Trojan/Shadowsocks — Xray-Core veya ham test)")
    tur = Prompt.ask("Seçim", choices=["1", "2"], default="2")

    cfg: Optional[ProxyConfig] = None
    use_xray = False
    mode = app_config.scan.mode

    if tur == "2":
        if not len(store):
            console.print("\n[yellow]Henüz kayıtlı config yok, hemen bir tane ekleyelim.[/]")
            cfg = add_config_inline(store)
            if cfg is None:
                return
        else:
            print_configs_table(store)
            idx = IntPrompt.ask("\nKullanılacak config #")
            cfg = store.get(idx)
            if cfg is None:
                console.print("[red]Geçersiz config numarası.[/]")
                return

        xray_mgr = xray_holder.get("mgr")
        if xray_mgr and xray_mgr.available:
            use_xray = Confirm.ask(
                "[bold]Xray-Core ile %100 GERÇEK tünel testi yapılsın mı?[/] "
                "(Hayır = daha hızlı ama daha az kesin ham TLS testi)", default=True)
        else:
            console.print("[yellow]Xray-Core şu an kullanılamıyor (Ayarlar'dan indirebilirsiniz). "
                          "Ham test ile devam edilecek.[/]")
        mode = "xray" if use_xray else "raw"

        if mode == "raw" and cfg is not None and cfg.is_quic_only_xhttp():
            console.print(
                "\n[yellow]Uyarı:[/] Bu config xhttp + alpn=h3 kullanıyor — "
                "Xray-core bunu TCP değil GERÇEK QUIC/UDP ile taşır. 'Ham test' "
                "modu TCP üzerinden TLS el sıkışması yaptığı için bu configi "
                "%100 doğrulayamaz (yanlış-pozitif/negatif verebilir). "
                "Kesin sonuç için Xray-Core tam tünel modunu kullanmanız önerilir."
            )
            if not Confirm.ask("Yine de ham test moduyla devam edilsin mi?", default=False):
                console.print("[dim]İptal edildi, Xray-Core kullanılamıyorsa Ayarlar'dan indirebilirsiniz.[/]")
                pause()
                return

    asn_label, networks, total = pick_targets_combined()
    if networks is None:
        pause()
        return

    ports = [cfg.port] if cfg is not None else app_config.scan.ports
    num_workers = app_config.scan.workers
    deep_concurrency = app_config.scan.deep_concurrency if use_xray else min(app_config.scan.deep_concurrency * 3, 120)
    result_path = default_result_path(mode, cfg)

    max_results = IntPrompt.ask("Kaç IP doğrulanınca tarama otomatik dursun? (0 = tümünü tara)",
                                default=app_config.scan.max_results)

    if Confirm.ask("Gelişmiş ayarları göstermek ister misiniz? (varsayılanlar genelde yeterlidir)", default=False):
        ports = parse_port_list(
            Prompt.ask("Taranacak port(lar)", default=",".join(str(p) for p in ports)), ports)
        num_workers = IntPrompt.ask("Eşzamanlı TCP ön-filtre işçi sayısı", default=num_workers)
        deep_concurrency = IntPrompt.ask(
            "Derin doğrulama eşzamanlılığı"
            + (" (her biri ayrı bir Xray-Core süreci açar)" if use_xray else ""),
            default=deep_concurrency)
        result_path = Prompt.ask("Sonuç dosyası", default=result_path)

    result_path, existing_results = resolve_result_path(result_path)
    context_key = make_context_key(mode, cfg, ports)

    known_bad_count = bad_cache.count(context_key)
    if known_bad_count:
        console.print(f"[dim]Bu bağlam için bilinen-geçersiz hafızasında {known_bad_count:,} IP var, "
                       f"bunlar otomatik atlanacak.[/]")

    active_xray_mgr = None
    if use_xray:
        active_xray_mgr = XrayCoreManager(binary_path=xray_holder["mgr"].binary_path,
                                           max_concurrent=deep_concurrency)

    scanner = Scanner(
        ips=ripe.iter_ips(networks), total=total, mode=mode, ports=ports, cfg=cfg,
        xray_manager=active_xray_mgr, num_workers=num_workers, deep_concurrency=deep_concurrency,
        result_path=result_path, max_results=max_results or None,
        bad_cache=bad_cache, context_key=context_key, existing_results=existing_results,
        tcp_timeout=app_config.network.tcp_timeout,
        tls_timeout=app_config.network.tls_timeout,
    )
    try:
        run_with_dashboard(scanner, asn_label, mode, cfg, use_xray, result_path)
    finally:
        if active_xray_mgr:
            active_xray_mgr.cleanup()
    pause()


# ============================================================================
# Configler (tek ekran: listele + ekle + sil)
# ============================================================================

def print_configs_table(store: ConfigStore) -> None:
    if not len(store):
        console.print("[yellow]Henüz kayıtlı config yok.[/]")
        return
    table = Table(title="Kayıtlı Configler")
    table.add_column("#", justify="right")
    table.add_column("İsim")
    table.add_column("Detay")
    table.add_column("Adres")
    table.add_column("Fragment")
    for i, c in enumerate(store.configs):
        table.add_row(str(i), c.name, c.short_desc(), f"{c.address}:{c.port}", "✓" if c.fragment else "-")
    console.print(table)


def add_config_inline(store: ConfigStore) -> Optional[ProxyConfig]:
    console.print(Panel("vless:// , vmess:// , trojan:// veya ss:// linkini yapıştırın.", border_style="cyan"))
    link = Prompt.ask("Link")
    cfg = parse_link(link)
    if cfg is None:
        console.print("[red]Link ayrıştırılamadı. Desteklenen protokoller: vless, vmess, trojan, ss.[/]")
        return None
    store.add(cfg)
    console.print(f"[green]Eklendi:[/] {cfg.name}  [{cfg.short_desc()}]  @ {cfg.address}:{cfg.port}")
    if cfg.fragment:
        console.print(f"[cyan]Fragment algılandı:[/] {cfg.fragment}")
    return cfg


def menu_configs(store: ConfigStore) -> None:
    while True:
        banner()
        print_configs_table(store)
        console.print("\n  [bold]e[/]) Yeni config ekle    [bold]s[/]) Config sil    [bold]0[/]) Geri")
        choice = Prompt.ask("Seçim", choices=["e", "s", "0"], default="0")
        if choice == "e":
            add_config_inline(store)
            pause()
        elif choice == "s":
            if len(store):
                idx = IntPrompt.ask("Silinecek # numarası")
                console.print("[green]Silindi.[/]" if store.delete(idx) else "[red]Geçersiz numara.[/]")
            else:
                console.print("[yellow]Silinecek config yok.[/]")
            pause()
        else:
            return


# ============================================================================
# Ayarlar (Xray-Core yönetimi + bilinen-geçersiz IP hafızası — tek ekran)
# ============================================================================

def menu_settings(xray_holder: dict, bad_cache: BadIPCache) -> None:
    while True:
        banner()
        mgr = xray_holder.get("mgr")
        info = get_manual_download_info()
        status = "[green]aktif[/]" if (mgr and mgr.available) else "[red]kapalı / bulunamadı[/]"

        console.print(Panel(
            f"Xray-Core: {status}\n"
            f"  İkili dosya: {mgr.binary_path if mgr else '-'}\n"
            f"  Bu sistem için beklenen dosya: [bold]{info['expected_asset']}[/]\n"
            f"  Resmi indirme sayfası: {info['releases_page']}\n\n"
            f"Bilinen-geçersiz IP hafızası: [bold]{bad_cache.count():,}[/] kayıt "
            f"({len(bad_cache.contexts())} bağlamda) — 30 günden eski kayıtlar otomatik silinir.",
            title="Durum", border_style="cyan",
        ))

        console.print("  [bold]1[/]) Xray-Core'u indir / güncelle")
        console.print("  [bold]2[/]) Xray-Core manuel indirme bilgisi göster")
        console.print("  [bold]3[/]) Xray-Core'u bu oturumda " +
                       ("devre dışı bırak" if (mgr and mgr.available) else "yeniden etkinleştir"))
        console.print("  [bold]4[/]) Bilinen-geçersiz IP hafızasını görüntüle")
        console.print("  [bold]5[/]) Bilinen-geçersiz IP hafızasını temizle")
        console.print("  [bold]0[/]) Geri")
        choice = Prompt.ask("Seçim", choices=["0", "1", "2", "3", "4", "5"], default="0")

        if choice == "1":
            with console.status("[cyan]İndiriliyor...[/]"):
                try:
                    path = download_latest_xray(progress_cb=lambda s, d: console.print(f"  [{s}] {d}"))
                    console.print(f"[green]Başarılı:[/] {path}")
                    xray_holder["mgr"] = XrayCoreManager(binary_path=path)
                except XrayDownloadError as e:
                    console.print(f"[red]{e}[/]")
            pause()
        elif choice == "2":
            console.print(Panel(
                f"1) Tarayıcıdan açın: {info['releases_page']}\n"
                f"2) '{info['expected_asset']}' dosyasını indirin\n"
                f"3) Zip'i açın, içindeki 'xray' (Windows'ta 'xray.exe') dosyasını şu klasöre koyun:\n"
                f"   {info['bin_dir']}\n"
                f"4) Linux/Mac/Termux'ta çalıştırma izni verin: chmod +x {info['bin_dir']}/xray",
                title="Manuel İndirme Adımları", border_style="yellow",
            ))
            pause()
        elif choice == "3":
            if mgr and mgr.available:
                xray_holder["mgr"] = None
                console.print("[yellow]Xray-Core bu oturum için devre dışı bırakıldı. "
                               "Tarama sihirbazında otomatik olarak ham test moduna geçilecek.[/]")
            else:
                existing_bin = find_existing_binary()
                xray_holder["mgr"] = XrayCoreManager(binary_path=existing_bin) if existing_bin else XrayCoreManager()
                console.print("[green]Xray-Core tekrar etkinleştirildi.[/]" if xray_holder["mgr"].available
                               else "[yellow]İkili dosya bulunamadı, önce indirin (Menü 1).[/]")
            pause()
        elif choice == "4":
            ctxs = bad_cache.contexts()
            if not ctxs:
                console.print("[yellow]Hafıza boş.[/]")
            else:
                table = Table(title="Bilinen-Geçersiz IP Hafızası")
                table.add_column("Bağlam")
                table.add_column("Kayıt sayısı", justify="right")
                for ctx, n in sorted(ctxs.items(), key=lambda x: -x[1]):
                    table.add_row(ctx, f"{n:,}")
                console.print(table)
            pause()
        elif choice == "5":
            if Confirm.ask("Tüm bilinen-geçersiz IP kayıtları silinsin mi? "
                           "(bir dahaki taramada her şey sıfırdan test edilir)", default=False):
                n = bad_cache.clear()
                console.print(f"[green]{n:,} kayıt silindi.[/]")
            pause()
        else:
            return


# ============================================================================
# CLI режим (неинтерактивный)
# ============================================================================

def run_cli_mode(app_config: AppConfig, store: ConfigStore, xray_holder: dict,
                 bad_cache: BadIPCache) -> None:
    """Запуск в неинтерактивном режиме с CLI аргументами."""
    from cf_scanner.config import create_parser

    parser = create_parser()
    args, _ = parser.parse_known_args()

    # Определяем конфиг прокси
    cfg: Optional[ProxyConfig] = None
    if args.link:
        cfg = parse_link(args.link)
        if cfg is None:
            console.print("[red]Ошибка: не удалось распознать прокси ссылку[/]")
            sys.exit(1)
        # Сохраняем конфиг
        store.add(cfg)
        console.print(f"[green]Добавлен конфиг:[/] {cfg.name}")

    # Определяем ASN/CIDR
    networks: List[ipaddress.IPv4Network] = []
    label_parts: List[str] = []

    asn = args.asn or app_config.scan.default_asn
    if asn:
        console.print(f"[dim]Получение префиксов для {asn} через RIPEstat...[/]")
        try:
            prefixes = asyncio.run(ripe.fetch_prefixes(asn))
            if prefixes:
                asn_networks = ripe.split_to_24(prefixes)
                networks.extend(asn_networks)
                label_parts.append(asn.upper())
        except Exception as e:
            console.print(f"[red]Ошибка получения данных RIPE: {e}[/]")

    if args.cidr:
        for cidr in args.cidr:
            try:
                if "/" in cidr:
                    networks.append(ipaddress.ip_network(cidr, strict=False))
                else:
                    networks.append(ipaddress.ip_network(cidr + "/32", strict=False))
                label_parts.append(cidr)
            except ValueError:
                console.print(f"[red]Неверный CIDR: {cidr}[/]")

    if not networks:
        console.print("[red]Не указаны цели для сканирования (ASN или CIDR)[/]")
        sys.exit(1)

    # Дедупликация
    seen = set()
    deduped = []
    for n in networks:
        if n not in seen:
            seen.add(n)
            deduped.append(n)

    total = sum(n.num_addresses for n in deduped)
    label = " + ".join(label_parts)

    # Настройки сканирования
    mode = args.scan or app_config.scan.mode
    ports = app_config.scan.ports
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            pass

    num_workers = args.workers or app_config.scan.workers
    deep_concurrency = args.deep_concurrency or app_config.scan.deep_concurrency
    max_results = args.max_results if args.max_results is not None else app_config.scan.max_results

    # Путь для результатов
    result_path = default_result_path(mode, cfg)
    _, existing_results = resolve_result_path(result_path)

    # Контекст для кэша
    context_key = make_context_key(mode, cfg, ports)

    # Xray-Core
    use_xray = mode == "xray" and not args.no_xray
    active_xray_mgr = None
    if use_xray:
        xray_path = args.xray or (xray_holder["mgr"].binary_path if xray_holder.get("mgr") else None)
        if xray_path:
            active_xray_mgr = XrayCoreManager(binary_path=xray_path, max_concurrent=deep_concurrency)
        else:
            console.print("[yellow]Xray-Core не найден, используется raw режим[/]")
            mode = "raw"
            use_xray = False

    # Создание сканера
    scanner = Scanner(
        ips=ripe.iter_ips(deduped), total=total, mode=mode, ports=ports, cfg=cfg,
        xray_manager=active_xray_mgr, num_workers=num_workers, deep_concurrency=deep_concurrency,
        result_path=result_path, max_results=max_results or None,
        bad_cache=bad_cache, context_key=context_key, existing_results=existing_results,
        tcp_timeout=app_config.network.tcp_timeout,
        tls_timeout=app_config.network.tls_timeout,
    )

    console.print(f"\n[bold cyan]Запуск сканирования:[/]")
    console.print(f"  Режим: {mode}")
    console.print(f"  Цели: {label} ({total:,} IP)")
    console.print(f"  Воркеры: {num_workers} TCP / {deep_concurrency} deep")
    console.print()

    try:
        run_with_dashboard(scanner, label, mode, cfg, use_xray, result_path)
    finally:
        if active_xray_mgr:
            active_xray_mgr.cleanup()


# ============================================================================
# Ana menü
# ============================================================================

def main() -> None:
    # Загружаем конфигурацию
    app_config = load_config(sys.argv[1:])

    # Обработка специальных команд
    if "--init-config" in sys.argv:
        create_default_config()
        sys.exit(0)

    if "--show-config" in sys.argv:
        show_config(app_config)
        sys.exit(0)

    # Проверка на CLI режим (если есть --scan или --cidr или --link)
    cli_mode = any(arg in sys.argv for arg in ["--scan", "--cidr", "--link", "--asn"])
    if cli_mode:
        store = ConfigStore()
        bad_cache = BadIPCache()
        existing_bin = find_existing_binary()
        xray_holder = {"mgr": XrayCoreManager(binary_path=existing_bin) if existing_bin else XrayCoreManager()}
        run_cli_mode(app_config, store, xray_holder, bad_cache)
        return

    # Интерактивный режим
    store = ConfigStore()
    bad_cache = BadIPCache()
    existing_bin = find_existing_binary()
    xray_holder = {"mgr": XrayCoreManager(binary_path=existing_bin) if existing_bin else XrayCoreManager()}

    while True:
        banner()
        mgr = xray_holder["mgr"]
        xray_status = "[green]●[/] aktif" if (mgr and mgr.available) else "[red]●[/] kapalı"
        console.print(f"Configler: {len(store)} kayıtlı   |   Xray-Core: {xray_status}   |   "
                      f"Bilinen geçersiz IP: {bad_cache.count():,}\n")
        console.print("  [bold]1[/]) Tarama Başlat")
        console.print("  [bold]2[/]) Configler (ekle / listele / sil)")
        console.print("  [bold]3[/]) Ayarlar (Xray-Core, bilinen-geçersiz hafızası)")
        console.print("  [bold]4[/]) Ayarları göster (--show-config)")
        console.print("  [bold]0[/]) Çıkış\n")

        choice = Prompt.ask("Seçim", choices=["0", "1", "2", "3", "4"], default="1")

        try:
            if choice == "1":
                menu_start_scan(store, xray_holder, bad_cache, app_config)
            elif choice == "2":
                menu_configs(store)
            elif choice == "3":
                menu_settings(xray_holder, bad_cache)
            elif choice == "4":
                show_config(app_config)
                pause()
            elif choice == "0":
                console.print("[cyan]Görüşmek üzere![/]")
                break
        except KeyboardInterrupt:
            console.print("\n[yellow]İptal edildi.[/]")
            pause()
        except Exception as e:
            console.print(f"[red]Beklenmeyen hata:[/] {e}")
            pause()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[cyan]Çıkılıyor...[/]")
        sys.exit(0)
