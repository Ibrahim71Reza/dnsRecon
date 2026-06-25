from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import requests

USER_AGENT = "dnsRecon/1.0 (+authorized-dns-recon)"


def _clean_name(name: str, domain: str) -> str | None:
    clean = name.strip().lower().strip(".")
    if not clean:
        return None
    if clean.startswith("*."):
        clean = clean[2:]
    if clean == domain or clean.endswith("." + domain):
        return clean
    return None


def _request_json(url: str, *, params: dict[str, str] | None, timeout: float, retries: int) -> tuple[Any | None, str | None]:
    last_error: str | None = None
    for attempt in range(max(1, retries + 1)):
        try:
            response = requests.get(url, params=params, timeout=timeout, headers={"User-Agent": USER_AGENT})
            response.raise_for_status()
            return response.json(), None
        except Exception as exc:  # pragma: no cover - network variability
            last_error = str(exc)
            if attempt < retries:
                time.sleep(min(1.5 * (attempt + 1), 4.0))
    return None, last_error


def _request_text(url: str, *, params: dict[str, str] | None, timeout: float, retries: int) -> tuple[str | None, str | None]:
    last_error: str | None = None
    for attempt in range(max(1, retries + 1)):
        try:
            response = requests.get(url, params=params, timeout=timeout, headers={"User-Agent": USER_AGENT})
            response.raise_for_status()
            return response.text, None
        except Exception as exc:  # pragma: no cover - network variability
            last_error = str(exc)
            if attempt < retries:
                time.sleep(min(1.5 * (attempt + 1), 4.0))
    return None, last_error


def fetch_crtsh_subdomains(domain: str, timeout: float = 8.0, retries: int = 2) -> dict:
    rows, error = _request_json("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=timeout, retries=retries)
    subdomains: set[str] = set()
    if isinstance(rows, list):
        for row in rows:
            name_value = str(row.get("name_value", "")) if isinstance(row, dict) else ""
            for name in name_value.splitlines():
                clean = _clean_name(name, domain)
                if clean:
                    subdomains.add(clean)
    return {"source": "crt.sh", "subdomains": sorted(subdomains), "error": error}


def fetch_anubis_subdomains(domain: str, timeout: float = 8.0, retries: int = 1) -> dict:
    rows, error = _request_json(f"https://jldc.me/anubis/subdomains/{domain}", params=None, timeout=timeout, retries=retries)
    subdomains: set[str] = set()
    if isinstance(rows, list):
        for name in rows:
            clean = _clean_name(str(name), domain)
            if clean:
                subdomains.add(clean)
    return {"source": "jldc-anubis", "subdomains": sorted(subdomains), "error": error}


def fetch_hackertarget_subdomains(domain: str, timeout: float = 8.0, retries: int = 1) -> dict:
    text, error = _request_text("https://api.hackertarget.com/hostsearch/", params={"q": domain}, timeout=timeout, retries=retries)
    subdomains: set[str] = set()
    if text and "error" not in text.lower():
        for line in text.splitlines():
            host = line.split(",", 1)[0].strip()
            clean = _clean_name(host, domain)
            if clean:
                subdomains.add(clean)
    return {"source": "hackertarget", "subdomains": sorted(subdomains), "error": error}


def fetch_otx_subdomains(domain: str, timeout: float = 8.0, retries: int = 1) -> dict:
    rows, error = _request_json(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", params={"limit": "1000"}, timeout=timeout, retries=retries)
    subdomains: set[str] = set()
    if isinstance(rows, dict):
        for item in rows.get("passive_dns", []) or []:
            clean = _clean_name(str(item.get("hostname", "")), domain)
            if clean:
                subdomains.add(clean)
    return {"source": "alienvault-otx", "subdomains": sorted(subdomains), "error": error}


def fetch_wayback_subdomains(domain: str, timeout: float = 8.0, retries: int = 1) -> dict:
    text, error = _request_text("https://web.archive.org/cdx", params={"url": f"*.{domain}/*", "output": "text", "fl": "original", "collapse": "urlkey"}, timeout=timeout, retries=retries)
    subdomains: set[str] = set()
    if text:
        for match in re.finditer(r"https?://([^/:?#]+)", text, flags=re.IGNORECASE):
            clean = _clean_name(match.group(1), domain)
            if clean:
                subdomains.add(clean)
    return {"source": "wayback-cdx", "subdomains": sorted(subdomains), "error": error}


def fetch_urlscan_subdomains(domain: str, timeout: float = 8.0, retries: int = 1) -> dict:
    rows, error = _request_json("https://urlscan.io/api/v1/search/", params={"q": f"domain:{domain}", "size": "10000"}, timeout=timeout, retries=retries)
    subdomains: set[str] = set()
    if isinstance(rows, dict):
        for item in rows.get("results", []) or []:
            page = item.get("page", {}) if isinstance(item, dict) else {}
            for key in ("domain", "url"):
                value = str(page.get(key, ""))
                if key == "url":
                    m = re.search(r"https?://([^/:?#]+)", value, re.I)
                    value = m.group(1) if m else value
                clean = _clean_name(value, domain)
                if clean:
                    subdomains.add(clean)
    return {"source": "urlscan", "subdomains": sorted(subdomains), "error": error}


def fetch_passive_subdomains(domain: str, timeout: float = 8.0, retries: int = 2) -> dict:
    """Collect passive subdomains from multiple public sources in parallel.

    v1 runs passive APIs concurrently so a slow/blocked source such as Wayback,
    OTX, or Anubis does not make the entire scan feel stuck. Every source is
    best-effort: failures are shown as evidence, not fatal errors.
    """
    reduced = max(0, retries - 1)
    jobs = [
        ("crt.sh", fetch_crtsh_subdomains, {"timeout": timeout, "retries": retries}),
        ("jldc-anubis", fetch_anubis_subdomains, {"timeout": timeout, "retries": reduced}),
        ("hackertarget", fetch_hackertarget_subdomains, {"timeout": timeout, "retries": reduced}),
        ("alienvault-otx", fetch_otx_subdomains, {"timeout": timeout, "retries": reduced}),
        ("wayback-cdx", fetch_wayback_subdomains, {"timeout": timeout, "retries": reduced}),
        ("urlscan", fetch_urlscan_subdomains, {"timeout": timeout, "retries": reduced}),
    ]
    sources: list[dict] = []
    with ThreadPoolExecutor(max_workers=len(jobs)) as executor:
        future_map = {executor.submit(func, domain, **kwargs): source for source, func, kwargs in jobs}
        for future in as_completed(future_map):
            source = future_map[future]
            try:
                sources.append(future.result())
            except Exception as exc:  # pragma: no cover - defensive source wrapper
                sources.append({"source": source, "subdomains": [], "error": f"{type(exc).__name__}: {exc}"})

    source_order = {source: i for i, (source, _, _) in enumerate(jobs)}
    sources.sort(key=lambda item: source_order.get(item.get("source", ""), 999))

    by_name: dict[str, set[str]] = {}
    for source in sources:
        for name in source.get("subdomains", []):
            by_name.setdefault(name, set()).add(source["source"])
    return {
        "source": "multi-passive",
        "sources": sources,
        "subdomains": sorted(by_name),
        "source_map": {name: sorted(srcs) for name, srcs in sorted(by_name.items())},
        "error": "; ".join(f"{s['source']}: {s['error']}" for s in sources if s.get("error")) or None,
    }
