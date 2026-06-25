from __future__ import annotations

import json
import os
import signal
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Iterable

from dnx.core.config import ScanConfig

TOOL_SPECS: dict[str, dict[str, object]] = {
    "subfinder": {
        "binary": "subfinder",
        "category": "passive-subdomains",
        "description": "ProjectDiscovery Subfinder passive subdomain enumeration",
        "runs": True,
    },
    "amass": {
        "binary": "amass",
        "category": "attack-surface-osint",
        "description": "OWASP Amass passive asset discovery",
        "runs": True,
    },
    "dnsx": {
        "binary": "dnsx",
        "category": "dns-resolution-enrichment",
        "description": "ProjectDiscovery dnsx DNS enrichment and wildcard-aware probing",
        "runs": True,
    },
    "puredns": {
        "binary": "puredns",
        "category": "active-dns-resolution",
        "description": "puredns wildcard-aware DNS resolving/bruteforce",
        "runs": True,
    },
    "shuffledns": {
        "binary": "shuffledns",
        "category": "active-dns-resolution",
        "description": "shuffleDNS massdns wrapper with wildcard handling",
        "runs": True,
    },
    "massdns": {
        "binary": "massdns",
        "category": "bulk-dns-resolution",
        "description": "MassDNS high-performance bulk DNS resolver",
        "runs": True,
    },
    "zdns": {
        "binary": "zdns",
        "category": "bulk-dns-measurement",
        "description": "ZDNS high-speed JSON DNS measurement engine",
        "runs": True,
    },
    "gotator": {
        "binary": "gotator",
        "category": "permutation-generation",
        "description": "Gotator DNS permutation generator",
        "runs": True,
    },
    "dnsviz": {
        "binary": "dnsviz",
        "category": "dnssec-diagnostics",
        "description": "DNSViz DNSSEC chain and DNS configuration diagnostics",
        "runs": True,
    },
    "nuclei": {
        "binary": "nuclei",
        "category": "dns-template-checks",
        "description": "ProjectDiscovery Nuclei DNS-template execution when templates are supplied",
        "runs": "templates-required",
    },
}

AUTO_TOOLS = ["subfinder", "dnsx", "puredns", "shuffledns", "massdns", "zdns", "gotator", "dnsviz"]
SLOW_TOOLS = {"amass"}


def _enabled_tools(config: ScanConfig) -> list[str]:
    requested = [item.lower().strip() for item in (config.external_tools or []) if item.strip()]
    if not config.use_external_tools:
        return []
    if not requested or "auto" in requested:
        requested = AUTO_TOOLS[:]
        if config.nuclei_templates:
            requested.append("nuclei")
    return [tool for tool in requested if tool in TOOL_SPECS]


def detect_external_tools(config: ScanConfig) -> dict:
    tools = []
    for name in _enabled_tools(config):
        binary = str(TOOL_SPECS[name]["binary"])
        path = shutil.which(binary)
        tools.append({
            "name": name,
            "binary": binary,
            "available": bool(path),
            "path": path,
            "category": TOOL_SPECS[name]["category"],
            "description": TOOL_SPECS[name]["description"],
            "runs": TOOL_SPECS[name].get("runs", True),
        })
    return {"enabled": config.use_external_tools, "requested": config.external_tools, "tools": tools}


def _run_command(cmd: list[str], timeout: float, *, stdin: str | None = None, max_output_lines: int = 50_000) -> tuple[int | None, str, str, float]:
    """Run a bounded command and cap stdout to avoid runaway adapter output.

    v1 uses communicate(timeout=...) instead of readline polling. Some tools,
    especially Amass, can stay quiet for a long time; readline can block and
    make dnsRecon look frozen. communicate(timeout=...) lets dnsRecon kill the process
    reliably even when the tool produces no output.
    """
    started = time.monotonic()

    def cap(text: str | None) -> str:
        if not text:
            return ""
        lines = text.splitlines()
        if len(lines) > max_output_lines:
            lines = lines[:max_output_lines] + ["# DNSRECON_OUTPUT_TRUNCATED"]
        return "\n".join(lines)

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if stdin is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = proc.communicate(input=stdin, timeout=max(1.0, float(timeout)))
            return proc.returncode, cap(stdout), stderr or "", round(time.monotonic() - started, 3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                proc.kill()
            stdout, stderr = proc.communicate()
            return None, cap(stdout), (stderr or "") + f"\ntimeout after {timeout}s", round(time.monotonic() - started, 3)
    except Exception as exc:  # pragma: no cover - defensive integration wrapper
        return None, "", f"{type(exc).__name__}: {exc}", round(time.monotonic() - started, 3)


def _clean_host(value: str, domain: str) -> str | None:
    item = value.strip().lower().strip(".")
    if not item:
        return None
    if item.startswith("{"):
        try:
            data = json.loads(item)
            for key in ("host", "name", "input", "domain", "question_name"):
                if data.get(key):
                    item = str(data[key]).strip().lower().strip(".")
                    break
        except Exception:
            return None
    # Accept common record-like output: host [A] ip, host CNAME target, etc.
    item = item.split()[0].strip().strip(",").strip(".")
    if item.startswith("*." ):
        item = item[2:]
    if item == domain or item.endswith("." + domain):
        return item
    return None


def _parse_hosts(text: str, domain: str, *, limit: int = 50_000) -> list[str]:
    out = set()
    for line in text.splitlines():
        if line.startswith("# DNSRECON_OUTPUT_TRUNCATED"):
            break
        host = _clean_host(line, domain)
        if host:
            out.add(host)
        if len(out) >= max(1, limit):
            break
    return sorted(out)


def _tool_timeout(config: ScanConfig) -> float:
    return max(1.0, float(config.external_tool_timeout or 0))


def _resolvers_args(config: ScanConfig) -> list[str]:
    if config.resolver_file:
        return ["-r", str(config.resolver_file)]
    if config.resolver:
        return ["-r", config.resolver]
    return []


def _wordlist_candidates(domain: str, config: ScanConfig, limit: int) -> list[str]:
    if not config.wordlist:
        return []
    words = []
    try:
        lines = Path(config.wordlist).read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []
    for line in lines:
        word = line.strip().split()[0].strip(".").lower() if line.strip() else ""
        if word and not word.startswith("#"):
            words.append(f"{word}.{domain}")
        if len(words) >= max(1, limit):
            break
    return words


def _write_temp_lines(values: Iterable[str]) -> Path:
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
    try:
        for value in values:
            if value:
                handle.write(str(value).strip() + "\n")
    finally:
        handle.close()
    return Path(handle.name)


def _source_record(name: str, cmd: list[str] | None, available: bool, hosts: list[str] | None = None, code: int | None = 0, error: str | None = None, *, diagnostic: dict | None = None, duration_seconds: float | None = None, skipped: bool = False) -> dict:
    return {
        "source": name,
        "command": " ".join(cmd or []),
        "available": available,
        "returncode": code,
        "count": len(hosts or []),
        "subdomains": hosts or [],
        "error": error,
        "duration_seconds": duration_seconds,
        "skipped": skipped,
        "diagnostic": diagnostic or {},
    }


def run_external_subdomain_sources(domain: str, config: ScanConfig) -> dict:
    """Run optional third-party recon binaries and normalize their output.

    dnsRecon never requires these tools. Missing or failing tools are represented as
    evidence, not fatal scan errors. Active external modules only run when dnsRecon is
    in active mode and bounded by the user's current wordlist/query budget.
    """
    inventory = detect_external_tools(config)
    if not config.use_external_tools:
        return {**inventory, "sources": [], "diagnostics": [], "subdomains": [], "source_map": {}, "error": None}

    all_names: dict[str, set[str]] = {}
    sources: list[dict] = []
    diagnostics: list[dict] = []
    timeout = _tool_timeout(config)
    output_limit = max(1000, min(config.external_candidate_limit, 250_000))
    available = {item["name"]: item for item in inventory["tools"] if item.get("available")}
    requested_raw = [x.lower().strip() for x in (config.external_tools or []) if x.strip()]
    auto_mode = not requested_raw or "auto" in requested_raw
    if auto_mode and shutil.which("amass"):
        sources.append(_source_record(
            "amass",
            None,
            True,
            [],
            None,
            "skipped in auto mode because Amass can be slow; run --tools amass explicitly for deep OSINT",
            skipped=True,
        ))

    def add_source(name: str, cmd: list[str], *, stdin: str | None = None) -> list[str]:
        code, stdout, stderr, duration = _run_command(cmd, timeout, stdin=stdin, max_output_lines=output_limit)
        hosts = _parse_hosts(stdout, domain, limit=config.external_candidate_limit)
        for host in hosts:
            all_names.setdefault(host, set()).add(name)
        error = None if code == 0 else (stderr.strip()[:800] or f"exit={code}")
        sources.append(_source_record(name, cmd, True, hosts, code, error, duration_seconds=duration))
        return hosts

    def add_diagnostic(name: str, cmd: list[str], *, stdin: str | None = None, parser: str = "text") -> None:
        code, stdout, stderr, duration = _run_command(cmd, timeout, stdin=stdin, max_output_lines=5000)
        payload: dict = {"parser": parser, "stdout_sample": stdout[:4000]}
        if parser == "json-lines":
            rows = []
            for line in stdout.splitlines()[:200]:
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue
            payload = {"parser": parser, "rows_sample": rows[:20], "row_count_sample": len(rows)}
        diagnostics.append({
            "source": name,
            "command": " ".join(cmd),
            "available": True,
            "returncode": code,
            "duration_seconds": duration,
            "error": None if code == 0 else (stderr.strip()[:800] or f"exit={code}"),
            **payload,
        })

    for name in ["subfinder", "amass"]:
        if name not in available:
            continue
        if name == "subfinder":
            add_source("subfinder", [available[name]["path"], "-silent", "-d", domain])
        elif name == "amass":
            add_source("amass", [available[name]["path"], "enum", "-passive", "-nocolor", "-d", domain])

    seed_hosts = sorted(all_names) or [domain]
    if "dnsx" in available and seed_hosts:
        cmd = [available["dnsx"]["path"], "-silent", "-a", "-aaaa", "-cname", *(_resolvers_args(config))]
        add_source("dnsx", cmd, stdin="\n".join(seed_hosts) + "\n")

    if "zdns" in available and seed_hosts:
        # ZDNS consumes names on stdin and returns JSON lines. Use it as a high-speed
        # cross-check for names dnsRecon already knows, not as an unbounded enumerator.
        add_diagnostic("zdns-A", [available["zdns"]["path"], "A"], stdin="\n".join(seed_hosts[: min(len(seed_hosts), 5000)]) + "\n", parser="json-lines")

    if "dnsviz" in available:
        # DNSViz CLI varies slightly by installation; this probe form is diagnostic.
        add_diagnostic("dnsviz", [available["dnsviz"]["path"], "probe", "-A", domain], parser="text")

    if "nuclei" in available:
        if config.nuclei_templates:
            for template in config.nuclei_templates:
                add_diagnostic("nuclei-dns", [available["nuclei"]["path"], "-silent", "-jsonl", "-u", domain, "-t", template], parser="json-lines")
        else:
            diagnostics.append({
                "source": "nuclei-dns",
                "available": True,
                "returncode": None,
                "error": "not run: provide --nuclei-templates to run DNS templates explicitly",
                "parser": "json-lines",
            })

    if config.active and config.wordlist:
        # Active external engines are bounded and scope-local.
        if "puredns" in available:
            cmd = [available["puredns"]["path"], "bruteforce", str(config.wordlist), domain, "--write", "-"]
            if config.resolver_file:
                cmd.extend(["--resolvers", str(config.resolver_file)])
            add_source("puredns", cmd)
        elif "shuffledns" in available:
            cmd = [available["shuffledns"]["path"], "-d", domain, "-w", str(config.wordlist), "-silent"]
            if config.resolver_file:
                cmd.extend(["-r", str(config.resolver_file)])
            add_source("shuffledns", cmd)
        elif "massdns" in available and config.resolver_file:
            words = _wordlist_candidates(domain, config, max(1, config.max_dns_queries // 3))
            candidate_path = _write_temp_lines(words)
            try:
                cmd = [available["massdns"]["path"], "-r", str(config.resolver_file), "-t", "A", "-o", "S", str(candidate_path)]
                add_source("massdns", cmd)
            finally:
                candidate_path.unlink(missing_ok=True)

        if "gotator" in available and seed_hosts:
            sub_path = _write_temp_lines(seed_hosts[:5000])
            perm_words = []
            try:
                perm_words = [line.strip().split()[0].strip(".") for line in Path(config.wordlist).read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip() and not line.strip().startswith("#")]
            except OSError:
                perm_words = []
            perm_path = _write_temp_lines(perm_words[:5000])
            try:
                cmd = [
                    available["gotator"]["path"],
                    "-sub", str(sub_path),
                    "-perm", str(perm_path),
                    "-depth", str(max(1, min(config.gotator_depth, 3))),
                    "-numbers", str(max(0, min(config.gotator_numbers, 20))),
                    "-mindup",
                ]
                add_source("gotator", cmd)
            finally:
                sub_path.unlink(missing_ok=True)
                perm_path.unlink(missing_ok=True)

    missing = [item for item in inventory["tools"] if not item.get("available")]
    for item in missing:
        sources.append(_source_record(item["name"], None, False, [], None, f"binary not found: {item['binary']}"))

    return {
        **inventory,
        "sources": sources,
        "diagnostics": diagnostics,
        "subdomains": sorted(all_names),
        "source_map": {name: sorted(srcs) for name, srcs in sorted(all_names.items())},
        "error": "; ".join(s["error"] for s in sources if s.get("error") and s.get("available")) or None,
    }
