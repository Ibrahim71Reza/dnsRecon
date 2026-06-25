from __future__ import annotations

from pathlib import Path
from typing import Optional
import shutil
import sys

import typer
from rich.console import Console
from rich.table import Table

from dnx import __version__
from dnx.core.target import normalize_target
from dnx.output.assets import write_asset_exports
from dnx.output.console import print_banner, print_terminal_report
from dnx.output.csv_report import write_csv_report
from dnx.output.html_report import write_html_report
from dnx.output.json_report import write_json_report
from dnx.output.markdown_report import write_markdown_report
from dnx.output.text_report import write_text_report
from dnx.scanner import build_config, run_scan
from dnx.modules.external_tools import TOOL_SPECS, AUTO_TOOLS

console = Console()
REPORT_FORMATS = {"json", "md", "markdown", "html", "txt", "text", "csv", "assets", "all"}


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"dnsRecon v{__version__}")
        raise typer.Exit()


def _parse_report_formats(value: Optional[str]) -> list[str]:
    if not value:
        return []
    formats = [item.strip().lower() for item in value.split(",") if item.strip()]
    unknown = [item for item in formats if item not in REPORT_FORMATS]
    if unknown:
        console.print(f"[red]Invalid report format:[/red] {', '.join(unknown)}")
        console.print("Valid formats: json, md, html, txt, csv, assets, all")
        raise typer.Exit(2)
    if "all" in formats:
        return ["json", "md", "html", "txt", "csv", "assets"]
    normalized = []
    for fmt in formats:
        fmt = {"markdown": "md", "text": "txt"}.get(fmt, fmt)
        if fmt not in normalized:
            normalized.append(fmt)
    return normalized


def main(
    target: Optional[str] = typer.Argument(None, help="Target domain, e.g. example.com"),
    mode: str = typer.Option("full", "--mode", "-m", help="Scan mode: full, passive, active, safe"),
    ultimate: bool = typer.Option(False, "--ultimate", help="Maximum authorized recon profile"),
    examples: bool = typer.Option(False, "--examples", help="Show copy-paste usage examples and exit"),
    doctor: bool = typer.Option(False, "--doctor", help="Check dnsRecon installation and optional OSS tool availability"),
    fast: bool = typer.Option(False, "--fast", help="Fast DNS-only scan: quick profile, 1.1.1.1 resolver, low timeouts, no WHOIS/AXFR/passive APIs"),
    profile: str = typer.Option("quick", "--profile", help="Scan profile: quick, balanced, deep, report"),
    output: Path = typer.Option(Path("reports"), "--output", "-o", help="Directory for optional reports"),
    report: Optional[str] = typer.Option(None, "--report", help="Optional reports: json,md,html,txt,csv,assets,all. Default: terminal only"),
    resolver: Optional[str] = typer.Option("1.1.1.1", "--resolver", "-r", help="Custom DNS resolver IP, e.g. 1.1.1.1"),
    resolver_file: Optional[Path] = typer.Option(None, "--resolver-file", help="File containing resolver IPs, one per line"),
    wordlist: Optional[Path] = typer.Option(None, "--wordlist", "-w", help="Subdomain wordlist for active discovery"),
    timeout: float = typer.Option(1.0, "--timeout", help="Per-query DNS/network timeout in seconds"),
    lifetime: Optional[float] = typer.Option(None, "--lifetime", help="Total DNS query lifetime in seconds"),
    retries: int = typer.Option(0, "--retries", help="DNS/passive HTTP retry count"),
    concurrency: int = typer.Option(50, "--concurrency", help="Concurrent DNS/HTTP/TLS workers"),
    rate_limit: float = typer.Option(0.0, "--rate-limit", help="Approximate DNS queries per second limit; 0 disables throttling"),
    verify_subdomains: bool = typer.Option(False, "--verify-subdomains", help="Resolve discovered passive/OSS subdomains"),
    max_verify: int = typer.Option(300, "--max-verify", help="Maximum discovered subdomains to verify/probe"),
    recursive_depth: int = typer.Option(0, "--recursive-depth", help="Controlled recursive discovery depth; 0 disables"),
    permutations: bool = typer.Option(False, "--permutations", help="Generate practical env/service subdomain permutations"),
    max_dns_queries: int = typer.Option(25000, "--max-dns-queries", help="Maximum active DNS query budget estimate"),
    compare_resolvers: Optional[str] = typer.Option(None, "--compare-resolvers", help="Comma-separated resolver IPs to compare"),
    scope_file: Optional[Path] = typer.Option(None, "--scope-file", help="Optional extra in-scope domains/subdomains, one per line"),
    exclude_file: Optional[Path] = typer.Option(None, "--exclude-file", help="Optional out-of-scope subdomains, one per line"),
    http_probe: bool = typer.Option(False, "--http-probe", help="Probe discovered hosts over HTTP/HTTPS where authorized"),
    tls_probe: bool = typer.Option(False, "--tls-probe", help="Inspect TLS certificates on port 443 where authorized"),
    oss: bool = typer.Option(False, "--oss", help="Use optional installed OSS recon binaries and merge results"),
    tools: Optional[str] = typer.Option("auto", "--tools", help="OSS tools to use: auto or comma list: subfinder,amass,dnsx,puredns,shuffledns,massdns,zdns,gotator,dnsviz,nuclei"),
    external_tool_timeout: float = typer.Option(25.0, "--external-tool-timeout", help="Timeout per optional external tool command"),
    external_candidate_limit: int = typer.Option(50000, "--external-candidate-limit", help="Max candidates accepted from optional external tools"),
    gotator_depth: int = typer.Option(2, "--gotator-depth", help="Gotator permutation depth when gotator is installed"),
    gotator_numbers: int = typer.Option(3, "--gotator-numbers", help="Gotator number mutation window when gotator is installed"),
    nuclei_templates: Optional[str] = typer.Option(None, "--nuclei-templates", help="Comma-separated Nuclei DNS template files/directories to run when nuclei is selected"),
    terminal_limit: int = typer.Option(1000, "--terminal-limit", help="Max rows per large terminal section; 0 means unlimited"),
    no_axfr: bool = typer.Option(False, "--no-axfr", help="Skip AXFR zone-transfer testing"),
    no_rdap: bool = typer.Option(False, "--no-rdap", help="Use WHOIS fallback instead of RDAP-first lookup"),
    no_redact_whois: bool = typer.Option(False, "--no-redact-whois", help="Do not redact WHOIS/RDAP raw sample in terminal/reports"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress terminal report; useful with --report"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Store verbose scan profile and resolver-health details"),
    whois_lookup: bool = typer.Option(False, "--whois/--no-whois", help="Enable WHOIS/RDAP lookup. Default: off for speed and offline reliability"),
    json_only: bool = typer.Option(False, "--json", help="Compatibility shortcut: write JSON report and print only its path"),
    version: bool = typer.Option(False, "--version", callback=_version_callback, is_eager=True, help="Show dnsRecon version"),
) -> None:
    """dnsRecon - terminal-first DNS intelligence for authorized pentesting."""
    if doctor or target == "doctor":
        _print_doctor()
        raise typer.Exit(0)
    if examples or not target:
        _print_examples()
        raise typer.Exit(0)
    _scan(
        target, mode, profile, ultimate, fast, output, report, resolver, resolver_file, wordlist, timeout, lifetime, retries,
        concurrency, rate_limit, verify_subdomains, max_verify, recursive_depth, permutations, max_dns_queries,
        compare_resolvers, scope_file, exclude_file, http_probe, tls_probe, oss, tools, external_tool_timeout,
        external_candidate_limit, gotator_depth, gotator_numbers, nuclei_templates, terminal_limit,
        not no_axfr, not no_rdap, not no_redact_whois, quiet, verbose, whois_lookup, json_only,
    )


def _scan(
    target_value: str,
    mode: str,
    profile: str,
    ultimate: bool,
    fast: bool,
    output: Path,
    report: Optional[str],
    resolver: Optional[str],
    resolver_file: Optional[Path],
    wordlist: Optional[Path],
    timeout: float,
    lifetime: Optional[float],
    retries: int,
    concurrency: int,
    rate_limit: float,
    verify_subdomains: bool,
    max_verify: int,
    recursive_depth: int,
    permutations: bool,
    max_dns_queries: int,
    compare_resolvers: Optional[str],
    scope_file: Optional[Path],
    exclude_file: Optional[Path],
    http_probe: bool,
    tls_probe: bool,
    oss: bool,
    tools: Optional[str],
    external_tool_timeout: float,
    external_candidate_limit: int,
    gotator_depth: int,
    gotator_numbers: int,
    nuclei_templates: Optional[str],
    terminal_limit: int,
    axfr: bool,
    rdap: bool,
    redact_whois: bool,
    quiet: bool,
    verbose: bool,
    whois: bool,
    json_only: bool,
) -> None:
    if fast:
        # Fast mode is for quick terminal feedback and troubleshooting. It avoids
        # slow passive APIs, WHOIS/RDAP, AXFR, and slow auto-selected tools.
        if mode == "full":
            mode = "active"
        profile = "quick"
        timeout = min(float(timeout), 1.0)
        lifetime = min(float(lifetime or 2.0), 2.0)
        retries = 0
        max_dns_queries = 0
        whois = False
        axfr = False
        if resolver is None:
            resolver = "1.1.1.1"
        if oss and (not tools or tools.strip().lower() == "auto"):
            tools = "subfinder,dnsx"

    if profile == "quick" and mode == "full":
        # A user asking for a quick profile usually expects a quick run, not a
        # full passive/API scan. Explicit --mode passive keeps passive behavior.
        mode = "active"

    if mode not in {"full", "passive", "active", "safe"}:
        console.print("[red]Invalid mode.[/red] Choose one of: full, passive, active, safe")
        raise typer.Exit(2)
    if profile not in {"quick", "balanced", "deep", "report"}:
        console.print("[red]Invalid profile.[/red] Choose one of: quick, balanced, deep, report")
        raise typer.Exit(2)

    report_formats = ["json"] if json_only else _parse_report_formats(report)

    if ultimate:
        mode = "full"
        profile = "deep"
        verify_subdomains = True
        permutations = True
        recursive_depth = max(recursive_depth, 1)
        http_probe = True
        tls_probe = True
        oss = True
        max_verify = max(max_verify, 1500)
        max_dns_queries = max(max_dns_queries, 100_000)
        concurrency = max(concurrency, 100)
        if not compare_resolvers:
            compare_resolvers = "1.1.1.1,8.8.8.8,9.9.9.9"

    try:
        target = normalize_target(target_value)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2)

    if oss:
        _precheck_oss_tools(tools, quiet=quiet or json_only)

    if not quiet and not json_only:
        print_banner()
        console.print(f"[cyan]Starting dnsRecon scan for[/cyan] [bold]{target.domain}[/bold] [dim]({mode}, {profile})[/dim]")
        if mode in {"active", "full"}:
            console.print("[yellow]Active checks enabled.[/yellow] Use only on assets you own or are explicitly authorized to test.")
        if oss:
            console.print("[yellow]OSS adapters enabled.[/yellow] dnsRecon will use installed tools only and merge normalized evidence.")

    config = build_config(
        mode=mode,
        resolver=resolver,
        resolver_file=resolver_file,
        output_dir=output,
        wordlist=wordlist,
        timeout=timeout,
        lifetime=lifetime,
        verify_subdomains=verify_subdomains,
        max_verify=max_verify,
        retries=retries,
        compare_resolvers_value=compare_resolvers,
        verbose=verbose,
        whois=whois,
        rdap=rdap,
        redact_whois=redact_whois,
        concurrency=concurrency,
        rate_limit=rate_limit,
        profile=profile,
        recursive_depth=recursive_depth,
        permutations=permutations,
        max_dns_queries=max_dns_queries,
        http_probe=http_probe,
        tls_probe=tls_probe,
        axfr=axfr,
        scope_file=scope_file,
        exclude_file=exclude_file,
        export_assets="assets" in report_formats,
        terminal_full=not quiet,
        report_formats=report_formats,
        use_external_tools=oss,
        external_tools_value=tools,
        external_tool_timeout=external_tool_timeout,
        external_candidate_limit=external_candidate_limit,
        gotator_depth=gotator_depth,
        gotator_numbers=gotator_numbers,
        nuclei_templates_value=nuclei_templates,
        terminal_limit=terminal_limit,
        fast_mode=fast,
    )
    if quiet or json_only:
        result = run_scan(target, config, mode=mode)
    else:
        with console.status("[bold green]Running dnsRecon modules...[/bold green]", spinner="dots"):
            result = run_scan(target, config, mode=mode)

    report_paths = _write_reports(result, output, report_formats)

    if json_only:
        console.print(str(report_paths[0]))
        return
    if not quiet:
        print_terminal_report(result)
        if report_paths:
            console.print("\n[bold green]Optional reports written:[/bold green]")
            for path in report_paths:
                console.print(f"  - {path}")
        else:
            console.print("\n[dim]No report files written. Use --report json,md,html,txt,csv,assets or --report all when you want files.[/dim]")



def _precheck_oss_tools(tools_value: Optional[str], *, quiet: bool = False) -> None:
    """Fail fast when the user requested only missing OSS tools.

    Without this precheck, a command such as
    `dnsRecon example.com --oss --tools subfinder,dnsx` can silently fall back
    to a normal native scan if both binaries are missing. That feels like the
    OSS phase is slow or stuck. Failing early is clearer and safer.
    """
    requested = [item.strip().lower() for item in (tools_value or "auto").split(",") if item.strip()]
    auto_mode = not requested or "auto" in requested
    if auto_mode:
        selected = list(AUTO_TOOLS)
        installed = [tool for tool in selected if shutil.which(str(TOOL_SPECS[tool]["binary"]))]
        if not installed and not quiet:
            console.print("[yellow]No auto OSS adapters are installed.[/yellow] Running native dnsRecon modules only. Use [bold]dnsRecon doctor[/bold] for setup guidance.")
        return

    valid = [tool for tool in requested if tool in TOOL_SPECS]
    invalid = [tool for tool in requested if tool not in TOOL_SPECS]
    if invalid:
        console.print(f"[red]Invalid OSS tool name:[/red] {', '.join(invalid)}")
        console.print("Valid tools: " + ", ".join(sorted(TOOL_SPECS)))
        raise typer.Exit(2)

    installed = [tool for tool in valid if shutil.which(str(TOOL_SPECS[tool]["binary"]))]
    missing = [tool for tool in valid if tool not in installed]
    if missing and not quiet:
        console.print(f"[yellow]Missing requested OSS tools:[/yellow] {', '.join(missing)}")
    if valid and not installed:
        console.print("[red]No requested OSS tools are installed, so the OSS scan was not started.[/red]")
        console.print("Run [bold]dnsRecon doctor[/bold], install the missing tools, or remove [bold]--oss[/bold] to run native dnsRecon only.")
        raise typer.Exit(2)


def _write_reports(result: dict, output: Path, formats: list[str]) -> list[Path]:
    paths: list[Path] = []
    if "json" in formats:
        paths.append(write_json_report(result, output))
    if "md" in formats:
        paths.append(write_markdown_report(result, output))
    if "html" in formats:
        paths.append(write_html_report(result, output))
    if "txt" in formats:
        paths.append(write_text_report(result, output))
    if "csv" in formats:
        paths.append(write_csv_report(result, output))
    if "assets" in formats:
        paths.extend(write_asset_exports(result, output))
    return paths


def _print_examples() -> None:
    console.print(f"[bold cyan]dnsRecon v{__version__}[/bold cyan]")
    console.print("Terminal-first DNS recon for authorized pentesters, bug bounty hunters, and defenders.")
    console.print("\n[bold]Fast DNS check:[/bold]             dnsRecon example.com --fast")
    console.print("[bold]Default terminal scan:[/bold]     dnsRecon example.com")
    console.print("[bold]Safe passive scan:[/bold]         dnsRecon example.com --mode safe")
    console.print("[bold]Optional reports:[/bold]          dnsRecon example.com --report json,md")
    console.print("[bold]OSS fast adapters:[/bold]         dnsRecon example.com --oss --tools subfinder,dnsx")
    console.print("[bold]Deep authorized scan:[/bold]      dnsRecon example.com --ultimate --wordlist wordlists/medium.txt --resolver-file resolvers/public.txt")
    console.print("[bold]Environment check:[/bold]         dnsRecon doctor")
    console.print("\nReports are not written by default. Use active/probing/OSS options only on authorized scope.")


def _print_doctor() -> None:
    console.print("[bold cyan]dnsRecon doctor[/bold cyan]")
    console.print(f"Version: [bold]{__version__}[/bold]")
    console.print(f"Python: {sys.version.split()[0]}")

    table = Table(title="Optional OSS tools", show_lines=True)
    table.add_column("Tool", style="bold")
    table.add_column("Auto")
    table.add_column("Installed")
    table.add_column("Path / Note")
    for name, spec in TOOL_SPECS.items():
        path = shutil.which(str(spec["binary"]))
        auto = "yes" if name in AUTO_TOOLS else "manual"
        note = path or "not found"
        if name == "amass" and path:
            note = f"{path} (manual only; use --tools amass for deep scans)"
        table.add_row(name, auto, "yes" if path else "no", note)
    console.print(table)
    console.print("\nRecommended first test:")
    console.print("  dnsRecon example.com --fast")
    console.print("\nRecommended OSS setup:")
    console.print("  install subfinder and dnsx, then run: dnsRecon example.com --oss --tools subfinder,dnsx")

def run() -> None:
    typer.run(main)


if __name__ == "__main__":
    run()
