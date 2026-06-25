from __future__ import annotations

import re
import socket
from typing import Any

import requests

REDACT_KEYS = {"registrant", "admin", "tech", "email", "phone", "street", "address"}


def _query_whois(server: str, query: str, timeout: float = 8.0) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode("utf-8"))
        chunks = []
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


def rdap_summary(domain: str, timeout: float = 8.0, redact: bool = True) -> dict:
    try:
        response = requests.get(f"https://rdap.org/domain/{domain}", timeout=timeout, headers={"User-Agent": "dnsRecon/1.0"})
        response.raise_for_status()
        data = response.json()
    except Exception as exc:  # pragma: no cover - network variability
        return {"source": "rdap", "summary": {}, "raw_sample": {}, "error": str(exc)}
    events: dict[str, list[str]] = {}
    for event in data.get("events", []) or []:
        action = event.get("eventAction")
        date = event.get("eventDate")
        if action and date:
            events.setdefault(action, []).append(date)
    ns = [item.get("ldhName", "").lower() for item in data.get("nameservers", []) or [] if item.get("ldhName")]
    summary: dict[str, Any] = {
        "handle": data.get("handle"),
        "ldhName": data.get("ldhName"),
        "status": data.get("status", []),
        "events": events,
        "nameservers": sorted(set(ns)),
        "registrar": _registrar_from_rdap(data),
    }
    raw_sample: Any = data if not redact else {k: v for k, v in data.items() if k.lower() not in REDACT_KEYS and k not in {"entities"}}
    return {"source": "rdap", "summary": summary, "raw_sample": raw_sample, "error": None}


def _registrar_from_rdap(data: dict) -> str | None:
    for entity in data.get("entities", []) or []:
        roles = entity.get("roles", [])
        if "registrar" in roles:
            vcard = entity.get("vcardArray", [])
            if len(vcard) >= 2:
                for item in vcard[1]:
                    if item and item[0] == "fn" and len(item) >= 4:
                        return item[3]
    return None


def whois_summary(domain: str, timeout: float = 8.0, *, prefer_rdap: bool = True, redact: bool = True) -> dict:
    if prefer_rdap:
        rdap = rdap_summary(domain, timeout=timeout, redact=redact)
        if not rdap.get("error"):
            rdap["fallback_whois"] = None
            return rdap
    try:
        iana = _query_whois("whois.iana.org", domain, timeout=timeout)
        match = re.search(r"^whois:\s*(\S+)", iana, flags=re.IGNORECASE | re.MULTILINE)
        server = match.group(1).strip() if match else None
        raw = _query_whois(server, domain, timeout=timeout) if server else iana
    except Exception as exc:
        return {"source": "whois", "server": None, "summary": {}, "raw_sample": "", "error": str(exc)}

    keys = ["Domain Name", "Registrar", "Creation Date", "Updated Date", "Registry Expiry Date", "Expiration Date", "Name Server", "DNSSEC", "Registrar Abuse Contact Email"]
    summary: dict[str, list[str]] = {}
    for key in keys:
        values = re.findall(rf"^{re.escape(key)}:\s*(.+)$", raw, flags=re.IGNORECASE | re.MULTILINE)
        if values:
            summary[key] = sorted(set(v.strip() for v in values))[:10]
    raw_sample = _redact_whois_raw(raw[:2500]) if redact else raw[:2500]
    return {"source": "whois", "server": server, "summary": summary, "raw_sample": raw_sample, "error": None}


def _redact_whois_raw(raw: str) -> str:
    lines = []
    for line in raw.splitlines():
        key = line.split(":", 1)[0].strip().lower()
        if any(token in key for token in REDACT_KEYS):
            lines.append(f"{line.split(':', 1)[0]}: [redacted]")
        else:
            lines.append(line)
    return "\n".join(lines)
