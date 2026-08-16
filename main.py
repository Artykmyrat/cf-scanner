#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CF-Scanner Pro
==============
Cloudflare Edge IP Scanner + Xray-Core tunnel verification
VLESS/VMess/Trojan/Shadowsocks | WS/gRPC/xHTTP | TLS/REALITY/Fragment

Usage:
    python3 main.py                           # Interactive mode
    python3 main.py --scan xray --asn AS13335  # CLI mode
    python3 main.py --lang ru                  # Set language
    python3 main.py --init-config              # Create config.toml
    python3 main.py --show-config              # Show current config
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
from cf_scanner.locale import t, set_language, get_language, get_language_name, get_available_languages
from cf_scanner.models import ProxyConfig
from cf_scanner.scanner import Scanner, load_existing_results
from cf_scanner.xray_manager import (
    XrayCoreManager, find_existing_binary, download_latest_xray,
    get_manual_download_info, XrayDownloadError,
)

console = Console()

DEFAULT_CF_PORTS = [443, 2053, 2083, 2087, 2096, 8443, 8880, 2052, 2082, 2086, 80]


# ============================================================================
# Helpers
# ============================================================================

def banner() -> None:
    console.clear()
    console.print(Panel.fit(
        "[bold cyan]CF-Scanner Pro[/]\n"
        "[dim]Cloudflare Edge IP Scanner  •  Xray-Core Tunnel Verification\n"
        "VLESS · VMess · Trojan · Shadowsocks  |  WS / gRPC / xHTTP  |  TLS / REALITY / Fragment[/]",
        border_style="cyan",
    ))


def pause() -> None:
    Prompt.ask(f"\n[dim]{t('press_enter')}[/]", default="", show_default=False)


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
    os.makedirs("results", exist_ok=True)
    name = slugify(cfg.name) if cfg is not None else "cloudflare"
    return os.path.join("results", f"{mode}_{name}.json")


def make_unique_path(path: str) -> str:
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
            console.print(f"[red]{t('targets_invalid_cidr')}:[/] {token}")
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
# Target selection: ASN and/or manual CIDR/IP — can be used together
# ============================================================================

def pick_targets_combined() -> Tuple[Optional[str], Optional[List[ipaddress.IPv4Network]], Optional[int]]:
    console.print(f"\n[bold]{t('targets_title')}[/] [dim]({t('targets_hint')})[/]")
    asn = Prompt.ask(t("targets_asn"), default="")
    manual_raw = Prompt.ask(t("targets_cidr"), default="")

    networks: List[ipaddress.IPv4Network] = []
    label_parts: List[str] = []

    asn = asn.strip()
    if asn:
        console.print(f"[dim]{t('targets_fetching')} {asn}...[/]")
        try:
            prefixes = asyncio.run(ripe.fetch_prefixes(asn))
        except Exception as e:
            console.print(f"[red]{t('targets_fetch_error')}: {e}[/]")
            prefixes = []
        if prefixes:
            asn_networks = ripe.split_to_24(prefixes)
            networks.extend(asn_networks)
            label_parts.append(asn.upper())
            console.print(f"[green]{asn.upper()}: {len(prefixes)} {t('targets_blocks')}[/]")
        else:
            console.print(f"[yellow]{asn.upper()}: {t('targets_not_found')}[/]")

    manual_raw = manual_raw.strip()
    if manual_raw:
        manual_networks = parse_manual_cidrs(manual_raw)
        if manual_networks:
            networks.extend(manual_networks)
            label_parts.append(f"{len(manual_networks)} {t('targets_manual_blocks')}")

    if not networks:
        console.print(f"[red]{t('targets_no_valid')}[/]")
        return None, None, None

    # Dedup
    seen = set()
    deduped = []
    for n in networks:
        if n not in seen:
            seen.add(n)
            deduped.append(n)

    total = sum(n.num_addresses for n in deduped)
    label = " + ".join(label_parts)
    console.print(f"[green]{t('targets_total')}: {len(deduped)}, {total:,} {t('targets_ip_count')}[/]")
    return label, deduped, total


# ============================================================================
# Result file: resume / new
# ============================================================================

def resolve_result_path(result_path: str):
    existing = load_existing_results(result_path)
    if existing:
        console.print(f"\n[yellow]'{result_path}' {t('results_already_exist')}: {len(existing)}[/]")
        choice = Prompt.ask(t("results_continue_or_new"),
                            choices=[t("results_continue"), t("results_new")],
                            default=t("results_continue"))
        if choice == t("results_new"):
            new_path = make_unique_path(result_path)
            console.print(f"[dim]{t('results_new_file')}: {new_path}[/]")
            return new_path, []
    return result_path, existing


# ============================================================================
# Scan Wizard
# ============================================================================

def menu_start_scan(store: ConfigStore, xray_holder: dict, bad_cache: BadIPCache,
                    app_config: AppConfig) -> None:
    banner()
    console.print(f"[bold]{t('scan_type')}[/]")
    console.print(f"  1) {t('scan_cloudflare_only')}")
    console.print(f"  2) {t('scan_with_config')}")
    tur = Prompt.ask(t("menu_selection"), choices=["1", "2"], default="2")

    cfg: Optional[ProxyConfig] = None
    use_xray = False
    mode = app_config.scan.mode

    if tur == "2":
        if not len(store):
            console.print(f"\n[yellow]{t('configs_empty')}, {t('configs_add_new')}[/]")
            cfg = add_config_inline(store)
            if cfg is None:
                return
        else:
            print_configs_table(store)
            idx = IntPrompt.ask(f"\n{t('configs_number')}")
            cfg = store.get(idx)
            if cfg is None:
                console.print(f"[red]{t('configs_invalid_number')}[/]")
                return

        xray_mgr = xray_holder.get("mgr")
        if xray_mgr and xray_mgr.available:
            use_xray = Confirm.ask(
                f"[bold]{t('xray_ask_verify')}[/] "
                f"{t('xray_ask_verify_hint')}", default=True)
        else:
            console.print(f"[yellow]{t('xray_unavailable')}[/]")
        mode = "xray" if use_xray else "raw"

        if mode == "raw" and cfg is not None and cfg.is_quic_only_xhttp():
            console.print(f"\n[yellow]{t('xray_raw_warning')}[/]")
            if not Confirm.ask(t("xray_raw_continue"), default=False):
                console.print(f"[dim]{t('xray_cancelled')}[/]")
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

    max_results = IntPrompt.ask(t("scan_max_results"),
                                default=app_config.scan.max_results)

    if Confirm.ask(t("scan_advanced_settings"), default=False):
        ports = parse_port_list(
            Prompt.ask(t("scan_ports"), default=",".join(str(p) for p in ports)), ports)
        num_workers = IntPrompt.ask(t("scan_tcp_workers"), default=num_workers)
        deep_concurrency = IntPrompt.ask(
            t("scan_deep_concurrency_xray") if use_xray else t("scan_deep_concurrency"),
            default=deep_concurrency)
        result_path = Prompt.ask(t("scan_result_file"), default=result_path)

    result_path, existing_results = resolve_result_path(result_path)
    context_key = make_context_key(mode, cfg, ports)

    known_bad_count = bad_cache.count(context_key)
    if known_bad_count:
        console.print(f"[dim]{known_bad_count:,} {t('scan_known_bad_skip')}[/]")

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
# Configs menu
# ============================================================================

def print_configs_table(store: ConfigStore) -> None:
    if not len(store):
        console.print(f"[yellow]{t('configs_empty')}[/]")
        return
    table = Table(title=t("configs_table_title"))
    table.add_column(t("configs_number"), justify="right")
    table.add_column(t("configs_name"))
    table.add_column(t("configs_detail"))
    table.add_column(t("configs_address"))
    table.add_column(t("configs_fragment"))
    for i, c in enumerate(store.configs):
        table.add_row(str(i), c.name, c.short_desc(), f"{c.address}:{c.port}", "✓" if c.fragment else "-")
    console.print(table)


def add_config_inline(store: ConfigStore) -> Optional[ProxyConfig]:
    console.print(Panel(t("configs_paste_link"), border_style="cyan"))
    link = Prompt.ask(t("configs_link"))
    cfg = parse_link(link)
    if cfg is None:
        console.print(f"[red]{t('configs_parse_error')}[/]")
        return None
    store.add(cfg)
    console.print(f"[green]{t('configs_added')}: {cfg.name}  [{cfg.short_desc()}]  @ {cfg.address}:{cfg.port}")
    if cfg.fragment:
        console.print(f"[cyan]{t('configs_fragment_detected')}: {cfg.fragment}[/]")
    return cfg


def menu_configs(store: ConfigStore) -> None:
    while True:
        banner()
        print_configs_table(store)
        console.print(f"\n  [bold]e[/]) {t('configs_add')}    [bold]s[/]) {t('configs_delete')}    [bold]0[/]) {t('configs_back')}")
        choice = Prompt.ask(t("menu_selection"), choices=["e", "s", "0"], default="0")
        if choice == "e":
            add_config_inline(store)
            pause()
        elif choice == "s":
            if len(store):
                idx = IntPrompt.ask(t("configs_delete_number"))
                console.print(f"[green]{t('configs_deleted')}[/]" if store.delete(idx) else f"[red]{t('configs_invalid_number')}[/]")
            else:
                console.print(f"[yellow]{t('configs_nothing_to_delete')}[/]")
            pause()
        else:
            return


# ============================================================================
# Settings menu
# ============================================================================

def menu_settings(xray_holder: dict, bad_cache: BadIPCache) -> None:
    while True:
        banner()
        mgr = xray_holder.get("mgr")
        info = get_manual_download_info()
        status = f"[green]{t('xray_active')}[/]" if (mgr and mgr.available) else f"[red]{t('xray_inactive')}[/]"

        console.print(Panel(
            f"Xray-Core: {status}\n"
            f"  {t('xray_binary')}: {mgr.binary_path if mgr else '-'}\n"
            f"  {t('xray_expected')}: [bold]{info['expected_asset']}[/]\n"
            f"  {t('xray_download_page')}: {info['releases_page']}\n\n"
            f"{t('xray_bad_ip_memory')}: [bold]{bad_cache.count():,}[/] {t('xray_records')} "
            f"({len(bad_cache.contexts())} {t('xray_contexts')}) — {t('xray_auto_expire')}.",
            title=t("menu_settings"), border_style="cyan",
        ))

        console.print(f"  [bold]1[/]) {t('xray_download_update')}")
        console.print(f"  [bold]2[/]) {t('xray_manual_info')}")
        console.print(f"  [bold]3[/]) {t('xray_toggle')}")
        console.print(f"  [bold]4[/]) {t('xray_view_bad_cache')}")
        console.print(f"  [bold]5[/]) {t('xray_clear_bad_cache')}")
        console.print(f"  [bold]0[/]) {t('configs_back')}")
        choice = Prompt.ask(t("menu_selection"), choices=["0", "1", "2", "3", "4", "5"], default="0")

        if choice == "1":
            with console.status(f"[cyan]{t('xray_downloading')}[/]"):
                try:
                    path = download_latest_xray(progress_cb=lambda s, d: console.print(f"  [{s}] {d}"))
                    console.print(f"[green]{t('xray_download_success')}: {path}[/]")
                    xray_holder["mgr"] = XrayCoreManager(binary_path=path)
                except XrayDownloadError as e:
                    console.print(f"[red]{e}[/]")
            pause()
        elif choice == "2":
            console.print(Panel(
                f"{t('settings_manual_step1')}: {info['releases_page']}\n"
                f"{t('settings_manual_step2')}: '{info['expected_asset']}'\n"
                f"{t('settings_manual_step3')}:\n"
                f"   {info['bin_dir']}\n"
                f"{t('settings_manual_step4')}: chmod +x {info['bin_dir']}/xray",
                title=t("xray_manual_steps"), border_style="yellow",
            ))
            pause()
        elif choice == "3":
            if mgr and mgr.available:
                xray_holder["mgr"] = None
                console.print(f"[yellow]{t('xray_disabled')}[/]")
            else:
                existing_bin = find_existing_binary()
                xray_holder["mgr"] = XrayCoreManager(binary_path=existing_bin) if existing_bin else XrayCoreManager()
                console.print(f"[green]{t('xray_reenabled')}[/]" if xray_holder["mgr"].available
                               else f"[yellow]{t('xray_not_found_download')}[/]")
            pause()
        elif choice == "4":
            ctxs = bad_cache.contexts()
            if not ctxs:
                console.print(f"[yellow]{t('xray_cache_empty')}[/]")
            else:
                table = Table(title=t("xray_cache_table_title"))
                table.add_column(t("xray_cache_context"))
                table.add_column(t("xray_cache_count"), justify="right")
                for ctx, n in sorted(ctxs.items(), key=lambda x: -x[1]):
                    table.add_row(ctx, f"{n:,}")
                console.print(table)
            pause()
        elif choice == "5":
            if Confirm.ask(t("xray_cache_clear_confirm"), default=False):
                n = bad_cache.clear()
                console.print(f"[green]{n:,} {t('xray_cache_cleared')}[/]")
            pause()
        else:
            return


# ============================================================================
# Language selection
# ============================================================================

def menu_language(app_config: AppConfig) -> None:
    """Language selection submenu."""
    console.print(f"\n[bold]{t('language_select')}[/]")
    langs = get_available_languages()
    for i, code in enumerate(langs, 1):
        marker = " ←" if code == app_config.locale.lang else ""
        console.print(f"  [bold]{i}[/]) {get_language_name(code)} ({code}){marker}")

    choice = Prompt.ask(t("lang_prompt"), choices=[str(i) for i in range(1, len(langs) + 1)],
                        default=str(langs.index(app_config.locale.lang) + 1))
    idx = int(choice) - 1
    if 0 <= idx < len(langs):
        app_config.locale.lang = langs[idx]
        set_language(langs[idx])


# ============================================================================
# CLI mode (non-interactive)
# ============================================================================

def run_cli_mode(app_config: AppConfig, store: ConfigStore, xray_holder: dict,
                 bad_cache: BadIPCache) -> None:
    """Run in non-interactive mode with CLI arguments."""
    from cf_scanner.config import create_parser

    parser = create_parser()
    args, _ = parser.parse_known_args()

    # Proxy config
    cfg: Optional[ProxyConfig] = None
    if args.link:
        cfg = parse_link(args.link)
        if cfg is None:
            console.print(f"[red]{t('configs_parse_error')}[/]")
            sys.exit(1)
        store.add(cfg)
        console.print(f"[green]{t('configs_added')}: {cfg.name}[/]")

    # ASN/CIDR targets
    networks: List[ipaddress.IPv4Network] = []
    label_parts: List[str] = []

    asn = args.asn or app_config.scan.default_asn
    if asn:
        console.print(f"[dim]{t('targets_fetching')} {asn}...[/]")
        try:
            prefixes = asyncio.run(ripe.fetch_prefixes(asn))
            if prefixes:
                asn_networks = ripe.split_to_24(prefixes)
                networks.extend(asn_networks)
                label_parts.append(asn.upper())
        except Exception as e:
            console.print(f"[red]{t('targets_fetch_error')}: {e}[/]")

    if args.cidr:
        for cidr in args.cidr:
            try:
                if "/" in cidr:
                    networks.append(ipaddress.ip_network(cidr, strict=False))
                else:
                    networks.append(ipaddress.ip_network(cidr + "/32", strict=False))
                label_parts.append(cidr)
            except ValueError:
                console.print(f"[red]{t('targets_invalid_cidr')}: {cidr}[/]")

    if not networks:
        console.print(f"[red]{t('targets_no_valid')}[/]")
        sys.exit(1)

    # Dedup
    seen = set()
    deduped = []
    for n in networks:
        if n not in seen:
            seen.add(n)
            deduped.append(n)

    total = sum(n.num_addresses for n in deduped)
    label = " + ".join(label_parts)

    # Scan settings
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

    # Result path
    result_path = default_result_path(mode, cfg)
    _, existing_results = resolve_result_path(result_path)

    # Cache context
    context_key = make_context_key(mode, cfg, ports)

    # Xray-Core
    use_xray = mode == "xray" and not args.no_xray
    active_xray_mgr = None
    if use_xray:
        xray_path = args.xray or (xray_holder["mgr"].binary_path if xray_holder.get("mgr") else None)
        if xray_path:
            active_xray_mgr = XrayCoreManager(binary_path=xray_path, max_concurrent=deep_concurrency)
        else:
            console.print(f"[yellow]Xray-Core {t('xray_not_found_download')}[/]")
            mode = "raw"
            use_xray = False

    # Create scanner
    scanner = Scanner(
        ips=ripe.iter_ips(deduped), total=total, mode=mode, ports=ports, cfg=cfg,
        xray_manager=active_xray_mgr, num_workers=num_workers, deep_concurrency=deep_concurrency,
        result_path=result_path, max_results=max_results or None,
        bad_cache=bad_cache, context_key=context_key, existing_results=existing_results,
        tcp_timeout=app_config.network.tcp_timeout,
        tls_timeout=app_config.network.tls_timeout,
    )

    console.print(f"\n[bold cyan]{t('cli_start_scan')}:[/]")
    console.print(f"  {t('scan_mode')}: {mode}")
    console.print(f"  {t('scan_target')}: {label} ({total:,} {t('targets_ip_count')})")
    console.print(f"  {t('scan_tcp_workers')}: {num_workers} TCP / {deep_concurrency} deep")
    console.print()

    try:
        run_with_dashboard(scanner, label, mode, cfg, use_xray, result_path)
    finally:
        if active_xray_mgr:
            active_xray_mgr.cleanup()


# ============================================================================
# Main menu
# ============================================================================

def main() -> None:
    # Load config
    app_config = load_config(sys.argv[1:])

    # Apply language from config
    set_language(app_config.locale.lang)

    # Handle special commands
    if "--init-config" in sys.argv:
        create_default_config()
        sys.exit(0)

    if "--show-config" in sys.argv:
        show_config(app_config)
        sys.exit(0)

    # Check for CLI mode
    cli_mode = any(arg in sys.argv for arg in ["--scan", "--cidr", "--link", "--asn"])
    if cli_mode:
        store = ConfigStore()
        bad_cache = BadIPCache()
        existing_bin = find_existing_binary()
        xray_holder = {"mgr": XrayCoreManager(binary_path=existing_bin) if existing_bin else XrayCoreManager()}
        run_cli_mode(app_config, store, xray_holder, bad_cache)
        return

    # Interactive mode
    store = ConfigStore()
    bad_cache = BadIPCache()
    existing_bin = find_existing_binary()
    xray_holder = {"mgr": XrayCoreManager(binary_path=existing_bin) if existing_bin else XrayCoreManager()}

    while True:
        banner()
        mgr = xray_holder["mgr"]
        xray_status = f"[green]●[/] {t('xray_active')}" if (mgr and mgr.available) else f"[red]●[/] {t('xray_inactive')}"
        console.print(f"{t('menu_configs')}: {len(store)}   |   Xray-Core: {xray_status}   |   "
                      f"{t('bad_ip_cache')}: {bad_cache.count():,}\n")
        console.print(f"  [bold]1[/]) {t('menu_scan')}")
        console.print(f"  [bold]2[/]) {t('menu_configs')}")
        console.print(f"  [bold]3[/]) {t('menu_settings')}")
        console.print(f"  [bold]4[/]) {t('menu_show_config')}")
        console.print(f"  [bold]5[/]) {t('language')} [{get_language_name(get_language())}]")
        console.print(f"  [bold]0[/]) {t('exit')}\n")

        choice = Prompt.ask(t("menu_selection"), choices=["0", "1", "2", "3", "4", "5"], default="1")

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
            elif choice == "5":
                menu_language(app_config)
            elif choice == "0":
                console.print(f"[cyan]{t('exit')}[/]")
                break
        except KeyboardInterrupt:
            console.print(f"\n[yellow]{t('exit')}[/]")
            pause()
        except Exception as e:
            console.print(f"[red]{e}[/]")
            pause()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(f"\n[cyan]{t('exit')}[/]")
        sys.exit(0)
