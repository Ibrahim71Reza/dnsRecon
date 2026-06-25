from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScanConfig:
    """Runtime configuration for one dnsRecon scan.

    Defaults are intentionally bounded enough for authorized external testing,
    CI, and lab environments. More aggressive discovery must be explicitly
    requested with deep/ultimate profiles and scoped inputs.
    """

    timeout: float = 2.0
    lifetime: float = 8.0
    resolver: str | None = None
    resolver_file: Path | None = None
    output_dir: Path = Path("reports")

    active: bool = True
    passive: bool = True
    brute_force: bool = True
    ct_logs: bool = True
    profile: str = "balanced"

    wordlist: Path | None = None
    verify_subdomains: bool = False
    max_verify: int = 300
    recursive_depth: int = 0
    permutations: bool = False
    max_dns_queries: int = 25_000

    retries: int = 1
    concurrency: int = 50
    rate_limit: float = 0.0
    compare_resolvers: list[str] = field(default_factory=list)

    verbose: bool = False
    whois: bool = True
    rdap: bool = True
    redact_whois: bool = True

    http_probe: bool = False
    tls_probe: bool = False
    takeover_check: bool = True
    axfr: bool = True
    export_assets: bool = True

    # v1 terminal-first operator experience.
    terminal_full: bool = True
    terminal_limit: int = 1000
    report_formats: list[str] = field(default_factory=list)
    module_timings: bool = True
    fast_mode: bool = False

    # Optional external adapters. These are never required to run dnsRecon.
    use_external_tools: bool = False
    external_tools: list[str] = field(default_factory=lambda: ["auto"])
    external_tool_timeout: float = 25.0
    external_candidate_limit: int = 50_000
    gotator_depth: int = 2
    gotator_numbers: int = 3
    nuclei_templates: list[str] = field(default_factory=list)

    scope_file: Path | None = None
    exclude_file: Path | None = None
    include_subdomains: list[str] = field(default_factory=list)
    exclude_subdomains: list[str] = field(default_factory=list)

    dkim_selectors: list[str] = field(default_factory=lambda: [
        "default", "google", "selector1", "selector2", "mail", "smtp", "dkim",
        "k1", "s1", "s2", "mandrill", "sendgrid", "mailgun", "zoho",
        "amazonses", "pm", "protonmail", "yandex", "mxvault",
    ])
    record_types: list[str] = field(default_factory=lambda: [
        "A", "AAAA", "CNAME", "NS", "SOA", "MX", "TXT", "CAA", "SRV", "DS",
        "DNSKEY", "HTTPS", "SVCB", "TLSA", "SSHFP", "NAPTR",
    ])
