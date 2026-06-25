<div align="center">
  <!-- You can replace this placeholder with a cool banner image -->
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:000000,100:00FF00&height=200&section=header&text=dnsRecon&fontSize=90&fontAlignY=35&animation=twinkling&fontColor=ffffff" alt="dnsRecon Banner" width="100%">

  **Terminal-first DNS intelligence for authorized security testing.**
  
  Fast DNS posture checks · Passive subdomain discovery · Mail security review · DNSSEC/CAA visibility · Clean reports

  [![Version](https://img.shields.io/badge/version-v1.0.3-blue.svg?style=for-the-badge)](#)
  [![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg?style=for-the-badge&logo=python&logoColor=white)](#)
  [![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Kali%20%7C%20WSL-lightgrey.svg?style=for-the-badge&logo=linux)](#)
  [![Status](https://img.shields.io/badge/status-Stable-success.svg?style=for-the-badge)](#)

</div>

<br>

> [!WARNING]
> ### ⚠️ Authorized Use Only
> `dnsRecon` is built for defenders, students, bug bounty operators, and pentesters working on assets they own or are explicitly authorized to test.
> **Use it only on:** Your own domains • Lab targets • CTF targets • Client-approved scopes • Written bug bounty scopes.
> *Do not use active or deep scans against systems where you do not have permission.*

---

## 💡 What is dnsRecon?

`dnsRecon` is a terminal-first DNS intelligence tool that gives quick, readable visibility into a domain’s DNS and security posture. 

The tool is designed to be practical: **fast output first, reports optional, no hard dependency on external recon tools.**

**It helps answer questions like:**
* 🔍 What DNS records does this domain expose?
* 🛡️ Is SPF, DMARC, CAA, or DNSSEC configured?
* ⚕️ Are there obvious DNS health issues?
* 🌐 What subdomains can be found from passive sources?
* 🛠️ Are optional OSS tools like Amass available?

---

## ✨ Core Features

| Feature | Description |
| :--- | :--- |
| ⚡ **Fast scan** | Quick DNS posture check in a few seconds |
| 🗂️ **DNS records** | A, AAAA, CNAME, NS, SOA, MX, TXT, CAA, DS, DNSKEY, HTTPS, etc. |
| 📧 **Mail security** | SPF, DMARC, DKIM selector checks, MTA-STS, TLS-RPT, BIMI |
| 🔐 **DNSSEC review** | DNSSEC evidence, state, algorithms, timeout-safe interpretation |
| 📜 **CAA review** | Certificate Authority Authorization visibility |
| 🏥 **DNS health** | TTL issues, delegation hints, NS/SOA checks |
| 🕵️ **Subdomain discovery**| Native passive and optional active discovery |
| 🧩 **OSS adapters** | Optional support for `Amass`, `subfinder`, `dnsx`, etc. |
| 🛡️ **Safe Evidence** | Timeouts are marked unknown, not false positives |
| 📊 **Rich Reports** | JSON, Markdown, HTML, TXT, CSV, assets export |

---

## 🚀 Getting Started

> [!NOTE]
> **Windows users** should run `dnsRecon` through WSL, Kali, or another Linux-compatible Python environment.

### Installation

**1. Clone or Extract the Project**
```bash
# Option A: From GitHub
git clone https://github.com/Ibrahim71Reza/dnsRecon.git
cd dnsRecon

# Option B: From ZIP
unzip dnsRecon-v1.0.3-final.zip
cd dnsRecon-v1.0.3
```

**2. Create a virtual environment**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**3. Install & Verify**
```bash
pip install -e .
dnsRecon --version
# Expected: dnsRecon v1.0.3
```

**4. Run Doctor (Check environment & optional tools)**
```bash
dnsRecon doctor
```

---

## 🕹️ Usage & Commands

> [!TIP]
> **Fast mode is the best first command.** It runs a quick bounded DNS posture check and avoids slow deep modules.
> ```bash
> dnsRecon example.com --fast
> ```

### Common Scenarios

| Goal | Command |
| :--- | :--- |
| **Default Scan** | `dnsRecon example.com` |
| **Fast Scan** | `dnsRecon example.com --fast` |
| **Passive-only Scan** | `dnsRecon example.com --mode passive --profile quick --no-whois --no-axfr` |
| **Balanced Authorized Scan** | `dnsRecon your-authorized-domain.com --profile balanced --mode full --timeout 2 --lifetime 5` |
| **Deep Authorized Scan** | `dnsRecon your-authorized-domain.com --ultimate --wordlist wordlists/medium.txt --resolver-file resolvers/public.txt` |
| **Generate All Reports** | `dnsRecon example.com --fast --report all` |

---

## 📊 Outputs & Reliability

### Report Formats
By default, dnsRecon prints to the terminal only. You can easily export findings:
```bash
dnsRecon example.com --fast --report json,md,html,txt,csv
```

### Risk Scoring
`dnsRecon` uses a score-style risk summary to help you prioritize:
* 🟢 **LOW:** No major issue detected.
* 🟡 **MODERATE / ELEVATED:** Review findings carefully.
* 🔴 **HIGH / CRITICAL:** Investigate immediately.
*(Always read the evidence and recommendations before reporting anything).*

### Timeout-Safe Evidence
Transient DNS errors are not treated as confirmed vulnerabilities. Timeouts and transient DNS errors are reported as *unknown*, not confirmed missing records, significantly reducing false positives during fast scans.

---

## 🛠️ Advanced Details

<details>
<summary><strong>📦 Optional OSS Tools</strong></summary>
<br>

`dnsRecon` can use external tools if installed, but they are **not required**. Check availability via `dnsRecon doctor`.

| Tool | Purpose |
| :--- | :--- |
| **Amass** | Deep passive/active subdomain discovery |
| **subfinder** | Passive subdomain discovery |
| **dnsx** | DNS resolution and validation |
| **puredns** | High-volume DNS resolving |
| **shuffledns** | DNS brute-force workflows |
| **massdns** | Fast resolver engine |
| **nuclei** | Manual template-based follow-up |

*Example (Running with Amass on an authorized domain):*
```bash
dnsRecon your-authorized-domain.com --oss --tools amass --external-tool-timeout 30
```
*If requested tools are missing, dnsRecon exits clearly instead of wasting time.*
</details>

<details>
<summary><strong>📂 Project Structure</strong></summary>
<br>

```text
dnsRecon/
├── dnx/                 # Core Python package
├── examples/            # Example usage files
├── resolvers/           # Resolver lists
├── tests/               # Test suite
├── wordlists/           # Wordlists
├── Dockerfile           # Basic Docker build
├── Dockerfile.oss       # Docker build with optional OSS tooling
├── Makefile             # Developer commands
├── pyproject.toml       # Python package config
├── requirements.txt     # Python dependencies
├── CHANGELOG_v1.md      # Release notes
├── LICENSE              # License
└── README.md            # This file
```
</details>

<details>
<summary><strong>🚑 Troubleshooting</strong></summary>
<br>

**Command not found**
```bash
source .venv/bin/activate
pip install -e .
```

**Old version still showing**
```bash
pip uninstall dnsrecon-cli -y
pip install -e .
hash -r
dnsRecon --version
```

**Scan seems slow**
Use fast mode: `dnsRecon example.com --fast`
Or reduce timeouts: `dnsRecon example.com --profile quick --timeout 1 --lifetime 2 --no-whois --no-axfr`

**DNSSEC or mail result says unknown**
This usually means DNS timeout or transient resolver failure. Re-run with larger timeout:
```bash
dnsRecon example.com --profile balanced --mode full --timeout 2 --lifetime 5
```
</details>

<details>
<summary><strong>👨‍💻 Development</strong></summary>
<br>

Run tests:
```bash
python -m pytest -q
```

Compile check:
```bash
python -m compileall -q dnx
```
</details>

---

<div align="center">
  <p><i>dnsRecon is not intended to replace every recon tool. It is a clean terminal-first DNS intelligence layer that gives fast, readable, evidence-aware results. Use it as your first DNS posture check, then escalate to deeper tooling only when needed.</i></p>
  
  **Version 1.0.3 | Stable Release**
  
  *(Note: Banner images and badges require an internet connection to render. If you are viewing this offline, functionality remains unaffected).*
</div>
