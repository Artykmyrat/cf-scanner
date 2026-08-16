"""
cf_scanner.config
==================
Централизованное управление конфигурацией из TOML файла и CLI аргументов.

Приоритет (от высшего к низшему):
  1. CLI аргументы
  2. Локальный config.toml (рядом с main.py)
  3. Глобальный ~/.config/cf-scanner/config.toml
  4. config.default.toml (значения по умолчанию)
"""
from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass, field
from typing import List, Optional

# Python 3.11+ имеет tomllib в стандартной библиотеке
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


DEFAULT_PORTS = [443, 2053, 2083, 2087, 2096, 8443, 8880, 2052, 2082, 2086, 80]


def _find_default_config_path() -> str:
    """Путь к config.default.toml рядом с этим файлом."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config.default.toml")


def _find_user_config_path() -> Optional[str]:
    """Путь к пользовательскому config.toml рядом с main.py."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config.toml")
    return path if os.path.exists(path) else None


def _find_global_config_path() -> Optional[str]:
    """Путь к глобальному конфигу ~/.config/cf-scanner/config.toml."""
    home = os.path.expanduser("~")
    path = os.path.join(home, ".config", "cf-scanner", "config.toml")
    return path if os.path.exists(path) else None


def _load_toml(path: str) -> dict:
    """Загружает TOML файл и возвращает dict."""
    if tomllib is None:
        return {}
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except (OSError, Exception):
        return {}


def _merge_dicts(base: dict, override: dict) -> dict:
    """Рекурсивно объединяет два dict (override перезаписывает base)."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _merge_dicts(result[key], value)
        else:
            result[key] = value
    return result


def _get_value(data: dict, dotted_key: str, default=None):
    """Получает значение из вложенного dict по точечному ключу.

    Пример: _get_value(data, "scan.workers", 400)
    """
    keys = dotted_key.split(".")
    current = data
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current


@dataclass
class ScanConfig:
    """Настройки сканирования."""
    mode: str = "cloudflare"
    workers: int = 400
    deep_concurrency: int = 25
    ports: List[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    max_results: int = 50
    autosave_every: int = 5
    default_asn: str = "AS13335"


@dataclass
class XrayConfig:
    """Настройки Xray-Core."""
    auto_download: bool = True
    max_concurrent: int = 25
    socks_port_start: int = 31000
    port_pool_size: int = 200


@dataclass
class CacheConfig:
    """Настройки кэша."""
    expiry_days: int = 30
    flush_every: int = 100


@dataclass
class NetworkConfig:
    """Сетевые таймауты."""
    tcp_timeout: float = 0.8
    tls_timeout: float = 5.0
    cloudflare_timeout: float = 5.0


@dataclass
class LocaleConfig:
    """Настройки языка."""
    lang: str = "en"


@dataclass
class UIConfig:
    """Настройки интерфейса."""
    refresh_rate: int = 7
    show_spinner: bool = True


@dataclass
class AppConfig:
    """Главный класс конфигурации."""
    locale: LocaleConfig = field(default_factory=LocaleConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    xray: XrayConfig = field(default_factory=XrayConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    ui: UIConfig = field(default_factory=UIConfig)


def load_config(cli_args: Optional[List[str]] = None) -> AppConfig:
    """Загружает конфигурацию из файлов и CLI.

    Приоритет: CLI > config.toml > ~/.config/... > config.default.toml
    """
    # 1. Загружаем все TOML файлы
    base = _load_toml(_find_default_config_path())
    global_conf = _load_toml(_find_global_config_path())
    user_conf = _load_toml(_find_user_config_path())

    # 2. Объединяем (поздние перезаписывают ранние)
    merged = base
    if global_conf:
        merged = _merge_dicts(merged, global_conf)
    if user_conf:
        merged = _merge_dicts(merged, user_conf)

    # 3. Создаём AppConfig из merged dict
    config = AppConfig(
        locale=LocaleConfig(
            lang=_get_value(merged, "locale.lang", "en"),
        ),
        scan=ScanConfig(
            mode=_get_value(merged, "scan.mode", "cloudflare"),
            workers=_get_value(merged, "scan.workers", 400),
            deep_concurrency=_get_value(merged, "scan.deep_concurrency", 25),
            ports=_get_value(merged, "scan.ports", list(DEFAULT_PORTS)),
            max_results=_get_value(merged, "scan.max_results", 50),
            autosave_every=_get_value(merged, "scan.autosave_every", 5),
            default_asn=_get_value(merged, "scan.default_asn", "AS13335"),
        ),
        xray=XrayConfig(
            auto_download=_get_value(merged, "xray.auto_download", True),
            max_concurrent=_get_value(merged, "xray.max_concurrent", 25),
            socks_port_start=_get_value(merged, "xray.socks_port_start", 31000),
            port_pool_size=_get_value(merged, "xray.port_pool_size", 200),
        ),
        cache=CacheConfig(
            expiry_days=_get_value(merged, "cache.expiry_days", 30),
            flush_every=_get_value(merged, "cache.flush_every", 100),
        ),
        network=NetworkConfig(
            tcp_timeout=_get_value(merged, "network.tcp_timeout", 0.8),
            tls_timeout=_get_value(merged, "network.tls_timeout", 5.0),
            cloudflare_timeout=_get_value(merged, "network.cloudflare_timeout", 5.0),
        ),
        ui=UIConfig(
            refresh_rate=_get_value(merged, "ui.refresh_rate", 7),
            show_spinner=_get_value(merged, "ui.show_spinner", True),
        ),
    )

    # 4. Применяем CLI аргументы (если есть)
    if cli_args is not None:
        parser = create_parser()
        args, _ = parser.parse_known_args(cli_args)
        config = apply_cli_args(config, args)

    return config


def create_parser() -> argparse.ArgumentParser:
    """Создаёт парсер CLI аргументов."""
    parser = argparse.ArgumentParser(
        prog="cf-scanner",
        description="CF-Scanner Pro — Cloudflare Edge IP Scanner with Xray-Core Verification",
    )

    # Язык
    parser.add_argument(
        "--lang", "-l",
        choices=["en", "ru", "tr"],
        help="Interface language (en, ru, tr)"
    )

    # Основные режимы
    parser.add_argument(
        "--scan", "-s",
        choices=["cloudflare", "raw", "xray"],
        help="Режим сканирования (по умолчанию: cloudflare)"
    )
    parser.add_argument(
        "--config", "-c",
        type=str,
        help="Путь к файлу конфигурации config.toml"
    )

    # Сетевые настройки
    parser.add_argument(
        "--asn",
        type=str,
        help="ASN для сканирования (по умолчанию: AS13335)"
    )
    parser.add_argument(
        "--cidr",
        type=str,
        nargs="+",
        help="CIDR/IP для сканирования (пример: 188.114.96.0/24 1.1.1.1)"
    )
    parser.add_argument(
        "--ports",
        type=str,
        help="Порты через запятую (по умолчанию: 443,2053,2083,...)"
    )

    # Производительность
    parser.add_argument(
        "--workers",
        type=int,
        help="Количество TCP воркеров"
    )
    parser.add_argument(
        "--deep-concurrency",
        type=int,
        help="Количество воркеров глубокой проверки"
    )
    parser.add_argument(
        "--max-results",
        type=int,
        help="Максимальное количество результатов (0 = без ограничений)"
    )

    # Xray-Core
    parser.add_argument(
        "--xray",
        type=str,
        help="Путь к бинарнику Xray-Core"
    )
    parser.add_argument(
        "--no-xray",
        action="store_true",
        help="Отключить Xray-Core (принудительно raw режим)"
    )

    # Конфиг прокси
    parser.add_argument(
        "--link",
        type=str,
        help="Прокси ссылка (vless://, vmess://, trojan://, ss://)"
    )

    # Утилиты
    parser.add_argument(
        "--init-config",
        action="store_true",
        help="Создать config.toml с настройками по умолчанию в текущей директории"
    )
    parser.add_argument(
        "--show-config",
        action="store_true",
        help="Показать текущую конфигурацию и выйти"
    )

    return parser


def apply_cli_args(config: AppConfig, args: argparse.Namespace) -> AppConfig:
    """Применяет CLI аргументы к конфигу."""
    if args.lang:
        config.locale.lang = args.lang

    if args.scan:
        config.scan.mode = args.scan

    if args.asn:
        config.scan.default_asn = args.asn

    if args.ports:
        try:
            config.scan.ports = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            pass

    if args.workers is not None:
        config.scan.workers = args.workers

    if args.deep_concurrency is not None:
        config.scan.deep_concurrency = args.deep_concurrency

    if args.max_results is not None:
        config.scan.max_results = args.max_results

    if args.no_xray:
        config.scan.mode = "raw"

    return config


def create_default_config() -> None:
    """Создаёт config.toml в текущей директории."""
    content = """# CF-Scanner Pro Configuration
# Раскомментируйте и измените нужные значения

[locale]
# lang = "en"                    # en | ru | tr

[scan]
# mode = "cloudflare"          # cloudflare | raw | xray
# workers = 400
# deep_concurrency = 25
# ports = [443, 2053, 2083, 2087, 2096, 8443, 8880, 2052, 2082, 2086, 80]
# max_results = 50
# default_asn = "AS13335"

[xray]
# auto_download = true
# max_concurrent = 25

[cache]
# expiry_days = 30
"""
    with open("config.toml", "w", encoding="utf-8") as f:
        f.write(content)
    print("✓ Создан config.toml в текущей директории")


def show_config(config: AppConfig) -> None:
    """Выводит текущую конфигурацию."""
    print("\n=== Текущая конфигурация ===\n")

    print("[locale]")
    print(f"  lang = {config.locale.lang!r}")

    print("\n[scan]")
    print(f"  mode = {config.scan.mode!r}")
    print(f"  workers = {config.scan.workers}")
    print(f"  deep_concurrency = {config.scan.deep_concurrency}")
    print(f"  ports = {config.scan.ports}")
    print(f"  max_results = {config.scan.max_results}")
    print(f"  default_asn = {config.scan.default_asn!r}")

    print("\n[xray]")
    print(f"  auto_download = {config.xray.auto_download}")
    print(f"  max_concurrent = {config.xray.max_concurrent}")

    print("\n[cache]")
    print(f"  expiry_days = {config.cache.expiry_days}")
    print(f"  flush_every = {config.cache.flush_every}")

    print("\n[network]")
    print(f"  tcp_timeout = {config.network.tcp_timeout}")
    print(f"  tls_timeout = {config.network.tls_timeout}")
    print(f"  cloudflare_timeout = {config.network.cloudflare_timeout}")

    print()
