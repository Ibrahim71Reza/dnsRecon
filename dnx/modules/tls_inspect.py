from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Iterable


def _inspect_one(host: str, port: int = 443, timeout: float = 4.0) -> dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
        san = []
        for key, value in cert.get("subjectAltName", []) or []:
            if key.lower() == "dns":
                san.append(value.lower())
        not_after = cert.get("notAfter")
        expires_in_days = None
        if not_after:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            expires_in_days = (exp - datetime.now(timezone.utc)).days
        return {
            "host": host,
            "port": port,
            "ok": True,
            "subject": cert.get("subject"),
            "issuer": cert.get("issuer"),
            "not_before": cert.get("notBefore"),
            "not_after": not_after,
            "expires_in_days": expires_in_days,
            "san_domains": sorted(set(san))[:200],
            "cipher": cipher,
            "error": None,
        }
    except Exception as exc:  # pragma: no cover - network variability
        return {"host": host, "port": port, "ok": False, "san_domains": [], "error": str(exc)}


def inspect_tls_hosts(hosts: Iterable[str], timeout: float = 4.0, concurrency: int = 20, limit: int = 500) -> list[dict]:
    clean_hosts = list(dict.fromkeys(h.strip().lower().strip(".") for h in hosts if h and h.strip()))[:limit]
    if not clean_hosts:
        return []
    results = []
    with ThreadPoolExecutor(max_workers=max(1, min(concurrency, 100))) as executor:
        future_map = {executor.submit(_inspect_one, host, 443, timeout): host for host in clean_hosts}
        for future in as_completed(future_map):
            try:
                results.append(future.result())
            except Exception as exc:  # pragma: no cover
                results.append({"host": future_map[future], "port": 443, "ok": False, "san_domains": [], "error": str(exc)})
    return sorted(results, key=lambda item: item.get("host", ""))
