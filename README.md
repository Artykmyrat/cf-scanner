<div align="center">

# CF-Scanner Pro

### Cloudflare Edge IP Scanner + Xray-Core Tunnel Verification

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)]()
[![Xray](https://img.shield.io/badge/Xray--Core-100%25%20Verified-red)](https://github.com/XTLS/Xray-core)

**Professional tool for scanning Cloudflare Edge IPs with full proxy protocol support**

[Features](#features) • [Installation](#installation) • [Quick Start](#quick-start) • [Configuration](#configuration) • [CLI Reference](#cli-reference) • [FAQ](#faq)

</div>

---

## Overview

CF-Scanner Pro is a high-performance Python tool that scans Cloudflare Edge IP addresses and verifies proxy configurations through real tunnel testing using Xray-Core. It supports all modern proxy protocols and transport methods.

### Why CF-Scanner Pro?

- **100% Accuracy** — Real tunnel verification through Xray-Core (not just TLS handshake)
- **High Performance** — 400+ concurrent TCP workers with smart backpressure
- **Multi-Protocol** — VLESS, VMess, Trojan, Shadowsocks
- **Multi-Transport** — TCP, WebSocket, gRPC, xHTTP (SplitHTTP)
- **Multi-Encryption** — TLS, REALITY, Fragment (Finalmask)
- **Multilingual** — English, Russian, Turkish interface
- **Smart Caching** — Bad IP memory with 30-day auto-expiry
- **Resume Support** — Continue interrupted scans without re-testing
- **Beautiful UI** — Real-time Rich dashboard with progress tracking

---

## Features

### Scanning Modes

| Mode | Description | Speed | Accuracy |
|------|-------------|-------|----------|
| `cloudflare` | Checks if IP is behind Cloudflare via `/cdn-cgi/trace` | ⚡ Fast | Medium |
| `raw` | TLS handshake verification without Xray-Core | 🔶 Medium | Good |
| `xray` | Full tunnel test through Xray-Core | 🐢 Slow | **100%** |

### Supported Protocols

| Protocol | Security | Transport |
|----------|----------|-----------|
| **VLESS** | TLS, REALITY | TCP, WS, gRPC, xHTTP |
| **VMess** | TLS | TCP, WS, gRPC, xHTTP |
| **Trojan** | TLS | TCP, WS, gRPC, xHTTP |
| **Shadowsocks** | None | TCP |

### Advanced Features

- **Fragment/Finalmask** — Bypass DPI with packet fragmentation
- **REALITY** — Next-gen TLS camouflage
- **xHTTP (SplitHTTP)** — HTTP/2 + QUIC transport
- **gRPC** — Multiplexed HTTP/2 transport
- **WebSocket** — CDN-friendly transport

---

## Installation

### Requirements

- Python 3.11 or higher
- pip (Python package manager)
- Optional: Xray-Core binary (auto-downloadable)

### Install from source

```bash
# Clone the repository
git clone https://github.com/Artykmyrat/cf-scanner.git
cd cf-scanner

# Install dependencies
pip install -r requirements.txt

# Run
python3 main.py
```

### Install dependencies only

```bash
pip install requests aiohttp aiohttp_socks rich
```

### Xray-Core (Optional)

Xray-Core is required only for `xray` mode (100% tunnel verification). You can:

1. **Auto-download** (recommended): Use Settings menu in the app
2. **Manual download**: Visit [Xray Releases](https://github.com/XTLS/Xray-core/releases/latest)
3. **System install**: `xray` must be in your PATH

---

## Quick Start

### Interactive Mode

```bash
python3 main.py
```

This launches the interactive menu:

```
┌─────────────────────────────────────────────────────────┐
│                      CF-Scanner Pro                      │
│  Cloudflare Edge IP Scanner • Xray-Core Tunnel Verify   │
└─────────────────────────────────────────────────────────┘

  1) Start Scan
  2) Configs (add / list / delete)
  3) Settings (Xray-Core, bad IP cache)
  4) Show config
  5) Language [English]
  0) Exit

Selection: 1
```

### CLI Mode

```bash
# Quick Cloudflare detection
python3 main.py --scan cloudflare --asn AS13335

# Full Xray verification with proxy link
python3 main.py --scan xray --link "vless://uuid@server:443?..."

# Scan specific CIDR ranges
python3 main.py --scan raw --cidr 104.16.0.0/13 172.64.0.0/13

# Russian interface
python3 main.py --lang ru --scan xray --asn AS13335
```

---

## Configuration

### Config File Hierarchy

Configuration is loaded from multiple sources (higher priority first):

1. **CLI arguments** — Override everything
2. **./config.toml** — Local config (git-ignored)
3. **~/.config/cf-scanner/config.toml** — Global config
4. **config.default.toml** — Defaults (included in repo)

### Create Config

```bash
python3 main.py --init-config
```

This creates `config.toml` in the current directory.

### Config Example

```toml
[locale]
lang = "en"  # en | ru | tr

[scan]
mode = "cloudflare"     # cloudflare | raw | xray
workers = 400           # TCP worker threads
deep_concurrency = 25   # Deep verification threads
ports = [443, 2053, 2083, 2087, 2096, 8443, 8880]
max_results = 50        # Stop after N results (0 = unlimited)
default_asn = "AS13335" # Cloudflare ASN

[xray]
auto_download = true
max_concurrent = 25

[cache]
expiry_days = 30

[network]
tcp_timeout = 0.8
tls_timeout = 5.0
```

### Show Current Config

```bash
python3 main.py --show-config
```

---

## CLI Reference

### Basic Options

| Flag | Description | Default |
|------|-------------|---------|
| `--scan`, `-s` | Scan mode: `cloudflare`, `raw`, `xray` | `cloudflare` |
| `--lang`, `-l` | Interface language: `en`, `ru`, `tr` | `en` |
| `--asn` | ASN to scan | `AS13335` |
| `--cidr` | CIDR ranges to scan | — |
| `--link` | Proxy config link | — |
| `--ports` | Ports to scan | All CF ports |

### Performance Options

| Flag | Description | Default |
|------|-------------|---------|
| `--workers` | TCP worker count | `400` |
| `--deep-concurrency` | Deep verification threads | `25` |
| `--max-results` | Stop after N results | `50` |

### Xray Options

| Flag | Description |
|------|-------------|
| `--xray` | Path to Xray-Core binary |
| `--no-xray` | Force raw mode (disable Xray) |

### Utility Commands

| Flag | Description |
|------|-------------|
| `--init-config` | Create config.toml with defaults |
| `--show-config` | Show current configuration |

---

## Usage Examples

### Example 1: Scan Cloudflare ASN

```bash
python3 main.py --scan cloudflare --asn AS13335
```

### Example 2: Verify Specific Configs

```bash
python3 main.py --scan xray \
  --link "vless://uuid@server:443?security=tls&type=ws&path=/ws#MyConfig" \
  --cidr 104.16.0.0/13
```

### Example 3: Batch Scan Multiple CIDRs

```bash
python3 main.py --scan raw \
  --cidr 104.16.0.0/13 172.64.0.0/13 173.245.48.0/20 \
  --ports 443,8443
```

### Example 4: Custom Performance

```bash
python3 main.py --scan xray \
  --workers 800 \
  --deep-concurrency 50 \
  --max-results 100
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        Producer                         │
│           (feeds IPs from ASN/CIDR ranges)              │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│                    TCP Workers (400)                     │
│           (parallel port scanning, 0.8s timeout)        │
└─────────────────────┬───────────────────────────────────┘
                      │ (backpressure)
                      ▼
┌─────────────────────────────────────────────────────────┐
│               Deep Verification Workers                 │
│              (Cloudflare/TLS/Xray tests)                │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│                    Results + Cache                       │
│          (JSON files + bad_ips.json cache)              │
└─────────────────────────────────────────────────────────┘
```

### Key Components

| Module | Description |
|--------|-------------|
| `scanner.py` | Two-stage funnel architecture |
| `checks.py` | TCP ping, TLS handshake, Cloudflare detection |
| `xray_manager.py` | Xray-Core process management |
| `link_parser.py` | Parse vless/vmess/trojan/ss links |
| `ripe.py` | RIPEstat API integration |
| `locale.py` | Multilingual support |
| `ui.py` | Rich live dashboard |
| `cache_store.py` | Bad IP memory with TTL |

---

## Multilingual Support

CF-Scanner Pro supports 3 languages:

| Language | Code |
|----------|------|
| English | `en` |
| Русский | `ru` |
| Türkçe | `tr` |

### Switch Language

**Interactive:** Menu option `5) Language`

**CLI:** `--lang ru`

**Config:**
```toml
[locale]
lang = "ru"
```

---

## Data Files

### configs.json
Stores your proxy configurations (VLESS/VMess/Trojan/SS links).

**⚠️ Contains passwords and UUIDs — do not share or commit!**

### bad_ips.json
Cache of IPs that failed verification. Auto-expires after 30 days.

### results/
Scan results in JSON format. Each entry contains:
- IP address
- Ping latency
- Open ports
- Verification method
- Tunnel latency (Xray mode)

---

## Troubleshooting

### Xray-Core not found

```bash
# Option 1: Auto-download via menu
python3 main.py
# Go to Settings → Download Xray-Core

# Option 2: Manual download
# Visit https://github.com/XTLS/Xray-core/releases
# Extract to bin/ directory
```

### Low scan speed

- Increase `--workers` (default: 400)
- Check network connection
- Some IPs may be rate-limited

### False negatives in raw mode

Raw mode only checks TLS handshake. For accurate results:
- Use `--scan xray` mode
- Or verify the IP works in your proxy client

### Connection errors

- Check firewall settings
- Verify proxy config is correct
- Some Cloudflare ports may be blocked in your region

---

## Performance Tips

1. **Use Xray mode** for 100% accuracy (slower but definitive)
2. **Use raw mode** for quick pre-filtering
3. **Increase workers** on fast connections: `--workers 800`
4. **Use CIDR ranges** instead of full ASN for targeted scanning
5. **Enable caching** — bad IPs are remembered across sessions

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [Xray-core](https://github.com/XTLS/Xray-core) — The core proxy framework
- [Rich](https://github.com/Textualize/rich) — Beautiful terminal UI
- [RIPEstat](https://stat.ripe.net/) — IP prefix data

---

<div align="center">

**If this tool helped you, consider giving it a ⭐**

</div>
