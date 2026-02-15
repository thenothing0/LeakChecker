<div align="center">

# 🔍 LeakChecker Pro v5.2

### Advanced OSINT & Leak Intelligence Framework — FINAL FIXED Edition

![Version](https://img.shields.io/badge/Version-5.2_FINAL-red?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Modules](https://img.shields.io/badge/Modules-20+-orange?style=for-the-badge)
![Dark Web](https://img.shields.io/badge/Dark_Web-8_Engines-purple?style=for-the-badge)

<pre>
██╗     ███████╗ █████╗ ██╗  ██╗
██║     ██╔════╝██╔══██╗██║ ██╔╝
██║     █████╗  ███████║█████╔╝
██║     ██╔══╝  ██╔══██║██╔═██╗
███████╗███████╗██║  ██║██║  ██╗
╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
     CHECKER PRO v5.2 FINAL
</pre>

**Surface Web + Deep Web + Dark Web scanning across 20+ intelligence sources**

[Features](#-features) •
[Installation](#-installation) •
[Usage](#-usage) •
[Modules](#-all-modules) •
[Threat Scoring](#-threat-scoring-system) •
[GitHub Filtering](#-github-smart-filtering) •
[API Keys](#-api-keys-setup) •
[Architecture](#-architecture) •
[Tor Setup](#-tor-setup) •
[FAQ](#-faq)

---

</div>

## ⚡ What's New in v5.2 FINAL

| Change | Description |
|:-------|:------------|
| 🐛 **All Bugs Fixed** | Every known issue from previous versions resolved |
| 🌑 **Dark Web Working** | 8 engines with verified `.onion` URLs |
| 🐙 **Smart GitHub Filter** | Removes AdGuard, filter lists, irrelevant repos automatically |
| 📊 **Threat Scoring v3** | Weighted scoring system with 25+ threat factors |
| 🔒 **SSL/TLS Analysis** | Certificate validation and expiry alerts |
| 🦠 **Malware Detection** | URLhaus + VirusTotal integration |
| 🔍 **Shodan InternetDB** | Free port and CVE scanning without API key |
| 📱 **Telegram OSINT** | Search leak channels and groups |
| 🤖 **Auto Dorking** | DuckDuckGo-powered automated dork search engine |
| 📦 **Wayback Machine** | Historical sensitive file discovery |
| 🗄️ **SQLite Database** | Persistent scan history and continuous monitoring |
| 📄 **HTML Reports** | Beautiful dark-themed interactive reports |
| 🔔 **Discord/Slack Alerts** | Real-time webhook notifications on HIGH/CRITICAL |

---

## 🎯 Features

### 🌐 Surface Web Intelligence — 15 Sources

| Module | Source | API Key | Description |
|:-------|:-------|:-------:|:------------|
| 🔓 HIBP | haveibeenpwned.com | ❌ Free | Breach detection via web scraping |
| 📊 EmailRep | emailrep.io | ⭐ Optional | Email reputation and breach history |
| 🔎 IntelX | intelx.io | ⭐ Free tier | Phonebook search for emails, domains, URLs |
| 🐙 GitHub | github.com | ⭐ Optional | Code leak detection with smart filtering |
| 🔍 LeakIX | leakix.net | ❌ Free | Exposed services and data leaks |
| 🔍 Shodan | internetdb.shodan.io | ❌ Free | Open ports and CVE detection |
| 🛡️ VirusTotal | virustotal.com | ⭐ Free tier | Malware and reputation analysis |
| 🦠 URLhaus | urlhaus.abuse.ch | ❌ Free | Malware URL database |
| 🌐 SecurityTrails | securitytrails.com | ⭐ Optional | Subdomain enumeration |
| 📦 Wayback | web.archive.org | ❌ Free | Historical sensitive files |
| 🔒 SSL Check | Direct connection | ❌ Free | Certificate analysis and expiry |
| 📋 WHOIS | WHOIS servers | ❌ Free | Domain registration intelligence |
| 🌐 DNS | crt.sh + AlienVault OTX | ❌ Free | Subdomain and DNS record enumeration |
| 🌐 Social | Gravatar + GitHub | ❌ Free | Social profile discovery |
| 🤖 Google Dorks | DuckDuckGo | ❌ Free | Automated dorking with 18+ templates |

### 🌑 Dark Web Intelligence — 8 Engines

| Engine | Type | Tor Required | Status |
|:-------|:-----|:------------:|:-------|
| 🔍 Ahmia | Surface gateway | ❌ | ✅ Primary engine |
| 🔍 DarkSearch | Surface API | ❌ | ✅ API-based search |
| 🔍 OnionLand | Surface gateway | ❌ | ✅ Web scraping |
| 🦆 DuckDuckGo | Surface fallback | ❌ | ✅ Fallback engine |
| 🔥 Torch | `.onion` direct | ✅ | ✅ 2 verified mirrors |
| 📁 JustDirs | `.onion` directory | ✅ | ✅ Onion directory listing |
| 🌾 Haystack | `.onion` search | ✅ | ✅ Full-text search |
| 🕷️ Direct Crawl | `.onion` paste sites | ✅ | ✅ Paste site crawling |

### 📱 Messaging Intelligence

| Module | Source | Description |
|:-------|:-------|:------------|
| 📱 Telegram | DuckDuckGo + TGStat | Search leak channels and groups |

### 🛡️ Security Analysis

| Check | Description |
|:------|:------------|
| 📧 SPF / DMARC / DKIM | Email authentication and security analysis |
| 🔒 SSL/TLS | Certificate validation, expiry, and protocol check |
| 🔍 Open Ports | Shodan InternetDB port and service scanning |
| 🦠 Malware | URLhaus + VirusTotal malware checks |
| 📊 CVE Detection | Known vulnerability matching via Shodan |

---

## 📦 Installation

### Prerequisites

    # Python 3.8 or higher
    python3 --version

    # Tor — optional, for dark web .onion access
    sudo apt install tor           # Debian / Ubuntu
    brew install tor               # macOS
    sudo pacman -S tor             # Arch Linux

### Quick Install

    # Clone the repository
    git clone https://github.com/thenothing0/LeakChecker.git
    cd LeakChecker

    # Run the setup script
    chmod +x setup_final.sh
    ./setup_final.sh

    # Install Python dependencies
    cd leak_checker
    pip install -r requirements.txt

    # Run the tool
    python3 main.py

### Virtual Environment Install

    git clone https://github.com/thenothing0/LeakChecker.git
    cd LeakChecker
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    python3 main.py

### Docker

Create a `Dockerfile`:

    FROM python:3.11-slim
    RUN apt-get update && apt-get install -y tor
    WORKDIR /app
    COPY . .
    RUN pip install -r requirements.txt
    CMD ["python3", "main.py"]

Build and run:

    docker build -t leakchecker .
    docker run -it leakchecker

---

## 🚀 Usage

### Interactive Mode

    python3 main.py

### Menu Options

    ╔═══════════════════════════════════════╗
    ║  [1]  📧  Full Email Scan            ║
    ║  [2]  🌐  Full Domain Scan           ║
    ║  [3]  🔑  Password Check             ║
    ║  [4]  🌑  Deep Web Search            ║
    ║  [5]  🤖  Auto Dork Search           ║
    ║  [6]  📱  Telegram Search            ║
    ║  [7]  🔄  Monitoring                 ║
    ║  [8]  📜  History                    ║
    ║  [9]  📊  Statistics                  ║
    ║  [10] 🔌  Tor Controls               ║
    ║  [11] 🧩  Credential Detector        ║
    ║  [0]  🚪  Exit                       ║
    ╚═══════════════════════════════════════╝

### Email Scan Example

    Select: 1
    📧 Email: target@example.com

    🎯 Scanning target@example.com | 11 modules...

     🔓 HIBP................. 3 found
     📊 EmailRep............. Clean
     🔎 IntelX............... 12 found
     🐙 GitHub............... 2 found (5 filtered)
     📋 Pastes............... 1 found
     🌐 Social............... 2 profiles
     🤖 Dorks................ 4 found
     🌑 Dark Web............. 4 found
     🌑 Forums............... 2 mentions
     📱 Telegram............. Clean

     ████████████████████████████░░░░░░░░░░░░  67.5/100
     Risk: 🟠 HIGH

### Domain Scan Example

    Select: 2
    🌐 Domain: example.com

    🎯 Scanning example.com | 20 modules...

     🌐 DNS.................. 45 subdomains
     🔒 Email Security....... Grade B
     📋 WHOIS................ 1,234 days old
     🔒 SSL/TLS.............. Valid (234 days)
     🔓 HIBP................. 2 breaches
     🔎 IntelX............... 8 found
     🔍 LeakIX............... 1 found
     🐙 GitHub............... 1 CRITICAL
     🐙 Commits.............. 3 found
     📋 Pastes............... Clean
     🔍 Shodan............... 8 ports, 3 CVEs
     🦠 URLhaus.............. Clean
     🛡️ VirusTotal........... Clean
     🌐 SecTrails............ 12 subdomains
     📦 Wayback.............. 6 sensitive
     🤖 Dorks................ 5 found
     🌑 Dark Web............. 2 mentions
     🌑 Forums............... 1 mention
     📱 Telegram............. Clean

     ██████████████████████████████████░░░░░░  82.0/100
     Risk: 🔴 CRITICAL

### Password Check

    Select: 3
    🔑 Password: ********

    🔴 PWNED! Seen 142,567 times!
    ⚠ Change this password immediately!

> **Note:** Password check uses k-Anonymity. Only the first 5 characters of the SHA-1 hash are sent to the API. Your password never leaves your machine.

### Deep Web Search

    Select: 4
    🌑 Target: example.com

    🌑 Searching 8 engines...

     ✅ Ahmia................ 3 results
     ✅ DarkSearch........... 1 result
     ✅ OnionLand............ 2 results
     ✅ DuckDuckGo........... 1 result
     ✅ Torch (via Tor)...... 2 results
     ✅ Haystack (via Tor)... 0 results
     ✅ JustDirs (via Tor)... 0 results

     Total: 9 findings across 7 engines

---

## 📊 Threat Scoring System

The threat score is calculated on a scale of 0 to 100 using weighted factors. The final score is capped at 100.

### 🔴 Critical Factors — 30 to 40 Points

| Factor | Weight | Trigger |
|:-------|:------:|:--------|
| 💰 Credentials Sold | **+40** | Dark web marketplace listing detected |
| 🔑 Password Leaked | **+35** | Plaintext passwords found in breach data |
| 🐙 GitHub CRITICAL | **+35** | `.env`, `private_key`, `id_rsa`, `wp-config` exposed |
| 🌑 Dark Web Mention | **+30** | Target found on `.onion` sites or leak forums |
| 🦠 Malware Detected | **+30** | URLhaus or VirusTotal malware association |

### 🟠 High Factors — 20 to 25 Points

| Factor | Weight | Trigger |
|:-------|:------:|:--------|
| 🛡️ VirusTotal Malicious | **+25** | One or more AV engines flagged domain |
| 🔓 URLhaus Malicious | **+25** | Domain found in malware URL database |
| 🐙 GitHub HIGH | **+25** | `api_key`, `secret`, `token`, `smtp` found in code |
| 🔓 Breach Found | **+20** | Match found in HIBP breach database |
| 🔍 Known CVEs | **+20** | Shodan InternetDB vulnerability data |

### 🟡 Medium Factors — 10 to 15 Points

| Factor | Weight | Trigger |
|:-------|:------:|:--------|
| 🐙 GitHub MEDIUM | **+15** | Potential credential mentions in repositories |
| 📋 Paste Found | **+15** | Target found on Pastebin or paste sites |
| 📱 Telegram Mention | **+15** | Target mentioned in leak channels |
| 🔒 SSL Expired | **+15** | SSL/TLS certificate has expired |
| 🔍 LeakIX Finding | **+15** | Exposed services or data leaks found |
| 📧 No Email Security | **+10** | SPF and DMARC records missing |
| 🔍 Many Open Ports | **+10** | More than 3 risky ports exposed |
| 🔎 IntelX Results | **+10** | Intelligence X phonebook data found |
| 🕐 Recent Breach | **+10** | Breach occurred less than 1 year ago |
| ⚠️ Bad Reputation | **+10** | VirusTotal reputation score below -5 |
| 🛡️ VT Suspicious | **+10** | Multiple engines flagged as suspicious |

### 🟢 Low Factors — 5 Points

| Factor | Weight | Trigger |
|:-------|:------:|:--------|
| 🔓 Multiple Breaches | **+5** | Per each additional breach found |
| 📧 Weak DMARC | **+5** | DMARC policy set to `p=none` |
| 🔒 SSL Expiring Soon | **+5** | Certificate expires in less than 30 days |
| 🌐 New Domain | **+5** | Domain created less than 90 days ago |

### 🎯 Risk Level Classification

| Score Range | Risk Level | Indicator | Required Action |
|:-----------:|:----------:|:---------:|:----------------|
| `75 — 100` | **CRITICAL** | 🔴 | Immediate action — change all passwords, enable 2FA |
| `50 — 74` | **HIGH** | 🟠 | Urgent attention — review and remediate findings |
| `25 — 49` | **MEDIUM** | 🟡 | Monitor closely — implement security improvements |
| `0 — 24` | **LOW** | 🟢 | Continue regular monitoring — maintain good practices |

### 📈 Score Calculation Example

    Target: user@example.com

    Found in LinkedIn breach (2012)     → Breach Found:       +20
    Passwords included in breach data   → Password Leaked:    +35
    Breach is older than 1 year         → Recent Breach:       +0
    Found on 2 dark web forums          → Dark Web Mention:   +30
    High-risk dark web mention (x1)     → Extra Risk:          +5
    Found on Pastebin                   → Paste Found:        +15
    GitHub: .env file with credentials  → GitHub CRITICAL:    +35
    GitHub: 3 irrelevant results        → Filtered Out:        +0
                                          ─────────────────────
                                          Raw Score:          140
                                          Capped at:          100
                                          Risk Level:    🔴 CRITICAL

### 🛡️ Auto-Generated Recommendations

| Detected Factor | Recommendation |
|:----------------|:---------------|
| Password Leaked | 🔑 Use unique passwords per service and a password manager |
| Dark Web Mention | 🌑 Enroll in identity protection monitoring service |
| GitHub CRITICAL | 🐙 Rotate all exposed credentials immediately |
| GitHub (any level) | 🐙 Enable `git-secrets` pre-commit hooks |
| No Email Security | 📧 Implement SPF + DMARC with `p=quarantine` |
| Weak DMARC | 📧 Upgrade DMARC policy to `p=quarantine` or `p=reject` |
| SSL Expired | 🔒 Renew SSL certificate immediately |
| SSL Expiring Soon | 🔒 Schedule SSL renewal before expiry date |
| Known CVEs | 🛡️ Apply security patches for identified CVEs |
| Risky Open Ports | 🔍 Close unnecessary ports and configure firewall |
| Malware / VT Malicious | 🦠 Investigate and scan server for compromise |
| Bad Reputation | ⚠️ Review VirusTotal detailed report and remediate |
| Paste Leak | 📋 Request paste removal from site operators |
| HIGH or CRITICAL risk | ⚠️ Change all passwords NOW and 🔐 enable 2FA everywhere |
| LOW risk | ✅ Continue monthly security scans |

---

## 🐙 GitHub Smart Filtering

### The Problem

Raw GitHub code search returns thousands of irrelevant results including AdGuard filter lists, wordlists, blocklists, and documentation files.

### The Solution

LeakChecker v5.2 automatically filters out irrelevant results and classifies real findings by sensitivity level.

### Sensitivity Classification

| Level | Category | Detected Files and Patterns |
|:-----:|:---------|:----------------------------|
| 🔴 **CRITICAL** | Config and Keys | `.env`, `.env.prod`, `.env.dev`, `.env_old` |
| | | `private_key`, `id_rsa`, `*.pem` |
| | | `wp-config.php`, `config.php`, `settings.py` |
| | | `database.yml`, `credentials`, `secrets` |
| | | `shadow`, `htpasswd` |
| 🟠 **HIGH** | Secrets and Auth | `password`, `passwd`, `pwd` |
| | | `api_key`, `apikey`, `API_KEY` |
| | | `secret`, `secret_key`, `SECRET` |
| | | `token`, `auth`, `smtp` |
| | | `database`, `db.js`, `db.py` |
| | | `credential`, `connection_string` |
| 🟡 **MEDIUM** | General Matches | Code files mentioning target |
| | | Non-sensitive configuration files |
| | | Documentation with target references |

### Filtered Repositories

    AdguardTeam/*                    FiltersRegistry/*
    AdguardBrowserExtension/*        MailScanner/*
    msticpy/*                        AdMetaNetwork/*
    web3-guard/*                     DriverSupportWebProtection/*
    Ad-BlockerResearch/*             openedr/*
    boost/beast/*                    lyncsmash/*
    jupyter-collection/*             cryptocurrency-scam-reports/*
    techguide/*                      empresas-que-usam-react/*
    trickest/inventory/*             payout-targets-data/*

### Filtered Files

    filter_9.txt                     filter_mobile_9.txt
    9_optimized.txt                  hostnames.txt
    assets.out                       .previous_assets
    alexa-top-20000-sites.txt        urls_large_data.cpp
    phishing.bad.sites.conf          kotlin-backend.md
    MOBILE.md                        PulsediveLookup.ipynb
    PulsediveLookup.html             cookies.txt

### Filtered Path Patterns

    filters/            filterlist/         blocklist/
    adblock/            adguard/            wordlist/
    alexa-top/          urls_large/         hostnames.txt
    assets.out          .previous_assets    phishing.bad

---

## 🔑 API Keys Setup

### 🆓 Free API Keys — Recommended

All API keys are **optional**. The tool works without any of them. Adding keys unlocks extra data sources and higher rate limits.

| Service | Free Tier Limit | Get Your Key | Env Variable |
|:--------|:---------------:|:-------------|:-------------|
| 🔎 **Intelligence X** | 10,000 queries/day | [intelx.io/account?tab=developer](https://intelx.io/account?tab=developer) | `INTELX_KEY` |
| 🐙 **GitHub** | 5,000 requests/hour | [github.com/settings/tokens](https://github.com/settings/tokens) | `GITHUB_TOKEN` |
| 🛡️ **VirusTotal** | 4 requests/minute | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) | `VT_API_KEY` |
| 📊 **EmailRep** | 25 requests/day | [emailrep.io](https://emailrep.io) | `EMAILREP_KEY` |
| 🌐 **SecurityTrails** | 50 requests/month | [securitytrails.com/app/signup](https://securitytrails.com/app/signup) | `ST_API_KEY` |
| 🔍 **Shodan** | Unlimited via InternetDB | [account.shodan.io](https://account.shodan.io) | `SHODAN_KEY` |

### Setting API Keys

**Linux and macOS:**

    # Add to ~/.bashrc or ~/.zshrc
    export INTELX_KEY="your-intelx-api-key"
    export GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    export VT_API_KEY="your-virustotal-api-key"
    export EMAILREP_KEY="your-emailrep-key"
    export ST_API_KEY="your-securitytrails-key"

    # Alerts — optional
    export DISCORD_WEBHOOK="https://discord.com/api/webhooks/123456/abcdef"
    export SLACK_WEBHOOK="https://hooks.slack.com/services/T00/B00/xxx"

    # Tor control — optional
    export TOR_PASSWORD="your-tor-password"

    # Apply changes
    source ~/.bashrc

**Windows PowerShell:**

    $env:INTELX_KEY = "your-intelx-api-key"
    $env:GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    $env:VT_API_KEY = "your-virustotal-api-key"

### ✅ Modules That Need NO API Key — 13 Modules

| # | Module | Source | What It Does |
|:-:|:-------|:-------|:-------------|
| 1 | 🔓 **HIBP** | haveibeenpwned.com | Breach detection via web scraping |
| 2 | 🔍 **Shodan InternetDB** | internetdb.shodan.io | Open ports and CVE scanning |
| 3 | 🦠 **URLhaus** | urlhaus.abuse.ch | Malware URL database check |
| 4 | 🌐 **DNS Enumeration** | crt.sh + AlienVault OTX | Subdomains and DNS records |
| 5 | 📧 **Email Security** | Direct DNS queries | SPF, DMARC, and DKIM analysis |
| 6 | 🔒 **SSL/TLS Check** | Direct connection | Certificate validation and expiry |
| 7 | 📋 **WHOIS** | WHOIS servers | Domain registration intelligence |
| 8 | 📦 **Wayback Machine** | web.archive.org | Historical sensitive files |
| 9 | 🤖 **Google Dorks** | DuckDuckGo | Automated dorking with 18+ templates |
| 10 | 🌑 **Dark Web Engines** | Ahmia + 7 engines | 8 dark web search engines |
| 11 | 📱 **Telegram Search** | DuckDuckGo | Leak channel discovery |
| 12 | 🌐 **Social Media** | Gravatar + GitHub | Profile discovery |
| 13 | 📋 **Paste Monitor** | Multiple paste sites | Surface and dark paste search |

---

## ⚙️ Configuration

### config.py Key Settings

    # Tor Configuration
    TOR_SOCKS_PORT = 9050              # Tor SOCKS proxy port
    TOR_CONTROL_PORT = 9051            # Tor control port for IP rotation
    TOR_REQUEST_TIMEOUT = 90           # Timeout for .onion requests (seconds)
    MAX_TOR_RETRIES = 3                # Retry count for failed requests
    AUTO_ROTATE_AFTER = 10             # Rotate Tor IP after N requests

    # Scanning Settings
    REQUEST_TIMEOUT = 15               # Surface web request timeout (seconds)
    RATE_LIMIT_DELAY = 2               # Delay between requests (seconds)
    MAX_CONCURRENT_SCANS = 5           # Maximum parallel scans

    # Monitoring
    MONITOR_INTERVAL = 3600            # Auto-check interval (seconds)

    # Alerts
    ALERT_ON_HIGH_RISK = True          # Send alerts on HIGH/CRITICAL findings
    ALERT_ON_NEW_BREACH = True         # Send alerts on newly discovered breaches

---

## 🏗️ Architecture

### Project Structure

    leak_checker/
    ├── main.py                          # Entry point and CLI interface
    ├── config.py                        # All configuration settings
    ├── requirements.txt                 # Python dependencies
    │
    ├── core/                            # Core engine
    │   ├── __init__.py
    │   ├── scanner.py                   # Main scanner orchestrator
    │   ├── threat_scorer.py             # Weighted threat score calculation
    │   ├── credential_detector.py       # Regex-based credential finder
    │   └── plugin_loader.py             # Dynamic plugin system
    │
    ├── network/                         # Network layer
    │   ├── __init__.py
    │   ├── tor_manager.py               # Tor SOCKS5 proxy + control port
    │   ├── session_manager.py           # HTTP session handler with rate limiting
    │   └── proxy_chain.py               # Proxy rotation support
    │
    ├── modules/                         # Intelligence modules
    │   ├── surface/                     # Surface web — 15 modules
    │   │   ├── hibp.py                  # Have I Been Pwned
    │   │   ├── emailrep.py              # EmailRep.io
    │   │   ├── intelx.py                # Intelligence X
    │   │   ├── github_search.py         # GitHub code + commit search
    │   │   ├── google_dorker.py         # Auto dorking engine
    │   │   ├── dns_enum.py              # DNS + email security
    │   │   ├── whois_intel.py           # WHOIS lookup
    │   │   ├── wayback.py               # Wayback Machine
    │   │   ├── social_media.py          # Social profile OSINT
    │   │   ├── leakix_search.py         # LeakIX
    │   │   ├── ssl_checker.py           # SSL/TLS analysis
    │   │   ├── shodan_free.py           # Shodan InternetDB
    │   │   ├── urlhaus_checker.py       # URLhaus malware check
    │   │   ├── virustotal_free.py       # VirusTotal analysis
    │   │   └── securitytrails_free.py   # SecurityTrails subdomains
    │   │
    │   ├── darkweb/                     # Dark web — 3 modules
    │   │   ├── onion_crawler.py         # 8-engine dark web search
    │   │   ├── forum_monitor.py         # Leak forum monitoring
    │   │   └── paste_monitor.py         # Surface + onion paste search
    │   │
    │   └── messaging/                   # Messaging — 1 module
    │       └── telegram_search.py       # Telegram OSINT
    │
    ├── alerts/                          # Alert system
    │   ├── webhook_alerts.py            # Discord and Slack webhooks
    │   ├── monitor_daemon.py            # Background monitoring daemon
    │   └── email_alerts.py              # SMTP email alerts
    │
    ├── database/                        # Persistence layer
    │   ├── models.py                    # SQLAlchemy ORM models
    │   └── db_manager.py                # Database operations
    │
    ├── reporting/                       # Report generation
    │   ├── report_generator.py          # JSON and TXT export
    │   ├── html_report.py               # HTML dark-themed reports
    │   ├── pdf_report.py                # PDF export
    │   └── encrypted_report.py          # Encrypted report export
    │
    ├── ui/                              # User interface
    │   ├── dashboard.py                 # Rich terminal dashboard
    │   ├── themes.py                    # Color themes
    │   └── animations.py               # Terminal animations
    │
    ├── api/                             # REST API
    │   ├── server.py                    # FastAPI server
    │   └── routes.py                    # API endpoints
    │
    ├── plugins/                         # Plugin system
    │   └── example_plugin.py            # Plugin template
    │
    ├── data/                            # Data files
    │   ├── dork_templates.json          # Custom dork templates
    │   └── breach_db.json               # Known breach database
    │
    └── results/                         # Scan output directory
        ├── *.json                       # JSON reports
        ├── *.txt                        # Text reports
        └── *.html                       # HTML reports

### Data Flow Diagram

    ┌─────────────────┐
    │    User CLI     │
    │   (main.py)     │
    └────────┬────────┘
             │
             ▼
    ┌─────────────────┐       ┌──────────────────┐
    │    Scanner      │──────▶│   Tor Manager    │──▶ .onion sites
    │   (core/)       │       └──────────────────┘
    └────────┬────────┘       ┌──────────────────┐
             │           ────▶│  Session Manager │──▶ Surface web
             │                └──────────────────┘
             ▼
    ┌─────────────────┐
    │    Modules      │
    │   (20+ srcs)    │
    │                 │
    │ ┌─────────────┐ │
    │ │  Surface    │ │──▶ HIBP, GitHub, Shodan, DNS, SSL ...
    │ │  (15 mods)  │ │
    │ └─────────────┘ │
    │ ┌─────────────┐ │
    │ │  Dark Web   │ │──▶ Ahmia, Torch, Haystack, Crawl ...
    │ │  (3 mods)   │ │
    │ └─────────────┘ │
    │ ┌─────────────┐ │
    │ │  Messaging  │ │──▶ Telegram
    │ │  (1 mod)    │ │
    │ └─────────────┘ │
    └────────┬────────┘
             │
             ▼
    ┌─────────────────┐       ┌──────────────────┐
    │  Threat Scorer  │──────▶│    Database      │
    │  (25+ factors)  │       │   (SQLite)       │
    └────────┬────────┘       └──────────────────┘
             │
             ├──▶ 📊 Dashboard    (Rich terminal UI)
             ├──▶ 📄 Reports      (JSON / TXT / HTML)
             └──▶ 🔔 Alerts       (Discord / Slack / Email)

---

## 🗄️ Database Schema

    -- Scan history
    CREATE TABLE scan_results (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        target          VARCHAR(255),
        target_type     VARCHAR(50),
        scan_date       DATETIME DEFAULT CURRENT_TIMESTAMP,
        threat_score    FLOAT DEFAULT 0.0,
        risk_level      VARCHAR(20),
        total_breaches  INTEGER DEFAULT 0,
        raw_results     JSON
    );

    -- Known breaches per target
    CREATE TABLE breaches (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        target          VARCHAR(255),
        breach_name     VARCHAR(255),
        breach_date     VARCHAR(50),
        pwn_count       INTEGER DEFAULT 0,
        data_types      TEXT,
        first_seen      DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Monitoring targets
    CREATE TABLE monitor_targets (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        target              VARCHAR(255) UNIQUE,
        target_type         VARCHAR(50),
        added_date          DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_checked        DATETIME,
        last_threat_score   FLOAT DEFAULT 0.0,
        is_active           BOOLEAN DEFAULT 1
    );

**Database location:**

    leak_checker/database/leakchecker.db

---

## 🧅 Tor Setup

### Install and Start Tor

    # Debian / Ubuntu
    sudo apt install tor
    sudo systemctl start tor
    sudo systemctl enable tor

    # macOS
    brew install tor
    brew services start tor

    # Arch Linux
    sudo pacman -S tor
    sudo systemctl start tor

    # Verify Tor is running
    curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip

### Enable Control Port — Optional

The control port allows LeakChecker to rotate your Tor IP automatically.

    # Edit Tor configuration
    sudo nano /etc/tor/torrc

    # Add these lines
    ControlPort 9051
    HashedControlPassword 16:YOUR_HASHED_PASSWORD
    CookieAuthentication 0

    # Generate hashed password
    tor --hash-password "your_password"

    # Restart Tor
    sudo systemctl restart tor

    # Set environment variable
    export TOR_PASSWORD="your_password"

### Without Tor

The tool works without Tor. Surface web engines still search dark web content through clearnet gateways:

| Works Without Tor | Requires Tor |
|:-------------------|:-------------|
| ✅ Ahmia (via ahmia.fi) | ❌ Torch (`.onion` direct) |
| ✅ DarkSearch (via API) | ❌ Haystack (`.onion` direct) |
| ✅ OnionLand (via clearnet) | ❌ JustDirs (`.onion` direct) |
| ✅ DuckDuckGo fallback | ❌ Direct paste site crawling |
| ✅ All 15 surface modules | |

---

## 🔔 Alerts

### Discord Webhook

    export DISCORD_WEBHOOK="https://discord.com/api/webhooks/123456/abcdef"

Sends rich embeds with:
- 🎯 Target name
- 📊 Threat score out of 100
- 🚨 Risk level with color coding
- 🔓 Breach count

### Slack Webhook

    export SLACK_WEBHOOK="https://hooks.slack.com/services/T00/B00/xxx"

### Email Alerts

Configure in code:

    from alerts.email_alerts import EmailAlerts

    alerts = EmailAlerts(
        smtp_host="smtp.gmail.com",
        smtp_port=587,
        smtp_user="your@gmail.com",
        smtp_pass="app-password",
        from_email="your@gmail.com",
        to_email="alerts@example.com"
    )

---

## 🔌 Plugin System

### Create a Custom Plugin

    # plugins/my_plugin.py
    from core.plugin_loader import PluginBase

    class MyCustomPlugin(PluginBase):
        name = "my_scanner"
        version = "1.0"
        description = "Custom leak scanner"

        def setup(self):
            self.api_url = "https://api.example.com"

        def run(self, target, target_type):
            return {
                "source": self.name,
                "target": target,
                "findings": [],
                "total": 0
            }

        def teardown(self):
            pass

Plugins placed in the `plugins/` directory are automatically discovered and loaded.

---

## 📄 Report Formats

### JSON Report

    {
        "target": "user@example.com",
        "target_type": "email",
        "scan_date": "2025-01-15T14:30:00",
        "threat": {
            "score": 67.5,
            "risk_level": "HIGH",
            "factors": [
                {
                    "factor": "Data Breach",
                    "impact": 20,
                    "details": "3 breach(es)"
                },
                {
                    "factor": "Password Leaked",
                    "impact": 35,
                    "details": "In: LinkedIn"
                }
            ],
            "recommendation": [
                "⚠️ Change all passwords NOW",
                "🔐 Enable 2FA on all accounts"
            ]
        },
        "hibp": {
            "breaches": [
                {
                    "name": "LinkedIn",
                    "date": "2012-05-05",
                    "pwn_count": 164611595
                }
            ]
        }
    }

### HTML Report

Dark-themed HTML report includes:
- 📊 Animated threat gauge
- 📋 Breach table with details
- 📈 Factor breakdown with impact scores
- 💡 Actionable recommendations
- 🌐 Opens in any web browser

### Text Report

Plain text report suitable for terminal output and email attachments.

---

## ❓ FAQ

<details>
<summary><b>Does it work without Tor?</b></summary>

Yes. 15+ surface modules and 4 dark web engines (Ahmia, DarkSearch, OnionLand, DuckDuckGo) work without Tor. Only 4 engines need Tor for direct `.onion` access (Torch, Haystack, JustDirs, Direct Crawl).

</details>

<details>
<summary><b>Does it work without any API keys?</b></summary>

Yes. 13 modules need zero API keys and zero registration. API keys are optional and unlock extra data sources with higher rate limits.

</details>

<details>
<summary><b>Is the password check safe?</b></summary>

Yes. The password check uses k-Anonymity via the HIBP Pwned Passwords API. Only the first 5 characters of the SHA-1 hash are sent to the server. Your actual password never leaves your machine.

</details>

<details>
<summary><b>Why are some GitHub results filtered?</b></summary>

Raw GitHub search returns thousands of false positives from AdGuard filter lists, security wordlists, and documentation files. The smart filter removes irrelevant repositories and files, showing only actual credential leaks classified by sensitivity level (CRITICAL, HIGH, MEDIUM).

</details>

<details>
<summary><b>How often should I scan?</b></summary>

- **Personal email:** Monthly
- **Business domain:** Weekly
- **After a known breach:** Immediately
- **Continuous:** Use monitoring mode (option 7) for automatic periodic checks

</details>

<details>
<summary><b>Tor connection failed. What do I do?</b></summary>

    # Check if Tor is running
    sudo systemctl status tor

    # Start Tor
    sudo systemctl start tor

    # Test the connection
    curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip

</details>

<details>
<summary><b>HIBP returns no results. Why?</b></summary>

HIBP free web scraping may be rate-limited. The tool automatically waits between requests using the configured `RATE_LIMIT_DELAY`. If you still get no results, wait 10 to 15 seconds and try again.

</details>

<details>
<summary><b>Can I add custom modules?</b></summary>

Yes. Use the plugin system. Create a Python file in the `plugins/` directory that extends `PluginBase`. It will be automatically discovered and loaded. See the Plugin System section for an example.

</details>

---

## ⚠️ Legal Disclaimer

> **This tool is designed for authorized security testing and personal use only.**
>
> **Permitted uses:**
> - ✅ Scanning your own email addresses and domains
> - ✅ Scanning targets with explicit written authorization
> - ✅ Security auditing and awareness training
> - ✅ Penetration testing with proper scope agreement
>
> **Prohibited uses:**
> - ❌ Scanning targets without permission
> - ❌ Unauthorized access to systems or data
> - ❌ Harassment, stalking, or doxxing
> - ❌ Any activity that violates local laws
>
> The authors are not responsible for misuse of this tool. Always comply with applicable laws and regulations. Dark web searches performed by this tool are passive and read-only. The tool does not interact with illegal services or marketplaces.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m "Add amazing feature"`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

### Development Setup

    git clone https://github.com/thenothing0/LeakChecker.git
    cd LeakChecker
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    pip install pytest black flake8

---

## 📜 License

    MIT License

    Copyright (c) 2025 LeakChecker Pro

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

---

## 🙏 Credits and Acknowledgments

### Data Sources

| Source | What We Use | Link |
|:-------|:------------|:-----|
| 🔓 **Have I Been Pwned** | Breach database and password check | [haveibeenpwned.com](https://haveibeenpwned.com) |
| 🔎 **Intelligence X** | Phonebook search and leak data | [intelx.io](https://intelx.io) |
| 🌑 **Ahmia.fi** | Tor hidden service search engine | [ahmia.fi](https://ahmia.fi) |
| 🔍 **Shodan InternetDB** | Free port and CVE data | [internetdb.shodan.io](https://internetdb.shodan.io) |
| 🦠 **URLhaus** | Malware URL database | [urlhaus.abuse.ch](https://urlhaus.abuse.ch) |
| 🛡️ **VirusTotal** | Multi-engine malware analysis | [virustotal.com](https://www.virustotal.com) |
| 🔍 **LeakIX** | Exposed service detection | [leakix.net](https://leakix.net) |
| 📊 **EmailRep** | Email reputation scoring | [emailrep.io](https://emailrep.io) |
| 🌐 **SecurityTrails** | DNS and subdomain intelligence | [securitytrails.com](https://securitytrails.com) |
| 📦 **Wayback Machine** | Historical web archive | [web.archive.org](https://web.archive.org) |
| 🔒 **crt.sh** | Certificate transparency logs | [crt.sh](https://crt.sh) |
| 🌐 **AlienVault OTX** | Open Threat Exchange DNS data | [otx.alienvault.com](https://otx.alienvault.com) |

### Libraries

| Library | Purpose | Link |
|:--------|:--------|:-----|
| 🎨 **Rich** | Beautiful terminal UI and tables | [github.com/Textualize/rich](https://github.com/Textualize/rich) |
| 🌐 **Requests** | HTTP client library | [docs.python-requests.org](https://docs.python-requests.org) |
| 🧅 **PySocks** | SOCKS proxy support for Tor | [pypi.org/project/PySocks](https://pypi.org/project/PySocks) |
| 🔌 **Stem** | Tor controller library | [stem.torproject.org](https://stem.torproject.org) |
| 🍲 **BeautifulSoup4** | HTML and XML parsing | [crummy.com/software/BeautifulSoup](https://www.crummy.com/software/BeautifulSoup) |
| 🗄️ **SQLAlchemy** | Database ORM | [sqlalchemy.org](https://www.sqlalchemy.org) |
| 🌐 **dnspython** | DNS resolution library | [dnspython.readthedocs.io](https://dnspython.readthedocs.io) |
| ⚡ **FastAPI** | REST API framework | [fastapi.tiangolo.com](https://fastapi.tiangolo.com) |

### Dark Web Search Engines

| Engine | Type | Verified URL |
|:-------|:-----|:-------------|
| 🔍 **Ahmia** | Surface gateway | `ahmia.fi` |
| 🔍 **DarkSearch** | Surface API | `darksearch.io` |
| 🔍 **OnionLand** | Surface gateway | `onionlandsearchengine.com` |
| 🦆 **DuckDuckGo** | Surface fallback | `duckduckgo.com` |
| 🔥 **Torch** | `.onion` direct | `xmh57jrk...noyd.onion` |
| 📁 **JustDirs** | `.onion` directory | `justdirs5...iad.onion` |
| 🌾 **Haystack** | `.onion` search | `haystak5n...fid.onion` |
| 📝 **StrongPaste** | `.onion` paste | `strongerw2...dad.onion` |

---

<div align="center">

### ⭐ Star this repository if it helped you

Built with ❤️ for the cybersecurity community

**[github.com/thenothing0/LeakChecker](https://github.com/thenothing0/LeakChecker)**

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)
![Tor](https://img.shields.io/badge/Tor-Supported-7D4698?style=flat-square&logo=tor-project&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=flat-square&logo=sqlite&logoColor=white)
![Rich](https://img.shields.io/badge/Rich-Terminal_UI-green?style=flat-square)

</div>
