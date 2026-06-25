from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable

import requests

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _probe_one(host: str, timeout: float = 4.0) -> dict:
    out = {"host": host, "urls": []}
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": "dnsRecon/1.0"})
            text = response.text[:20000] if response.text else ""
            title_match = TITLE_RE.search(text)
            title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:160] if title_match else None
            out["urls"].append({
                "url": url,
                "final_url": response.url,
                "status_code": response.status_code,
                "title": title,
                "server": response.headers.get("server"),
                "content_type": response.headers.get("content-type"),
                "content_length": response.headers.get("content-length"),
                "error": None,
            })
        except Exception as exc:  # pragma: no cover - network variability
            out["urls"].append({"url": url, "final_url": None, "status_code": None, "title": None, "server": None, "content_type": None, "content_length": None, "error": str(exc)})
    out["alive"] = any(item.get("status_code") for item in out["urls"])
    return out


def probe_http_hosts(hosts: Iterable[str], timeout: float = 4.0, concurrency: int = 20, limit: int = 500) -> list[dict]:
    clean_hosts = list(dict.fromkeys(h.strip().lower().strip(".") for h in hosts if h and h.strip()))[:limit]
    if not clean_hosts:
        return []
    results = []
    with ThreadPoolExecutor(max_workers=max(1, min(concurrency, 100))) as executor:
        future_map = {executor.submit(_probe_one, host, timeout): host for host in clean_hosts}
        for future in as_completed(future_map):
            try:
                results.append(future.result())
            except Exception as exc:  # pragma: no cover
                results.append({"host": future_map[future], "alive": False, "urls": [], "error": str(exc)})
    return sorted(results, key=lambda item: item.get("host", ""))
