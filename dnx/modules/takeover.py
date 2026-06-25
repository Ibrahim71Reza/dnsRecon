from __future__ import annotations

PROVIDERS = {
    "AWS S3 / CloudFront": ["amazonaws.com", "s3.amazonaws.com", "cloudfront.net"],
    "Azure": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net", "azureedge.net"],
    "GitHub Pages": ["github.io"],
    "Heroku": ["herokuapp.com", "herokudns.com"],
    "Cloudflare Pages": ["pages.dev"],
    "Netlify": ["netlify.app", "netlifyglobalcdn.com"],
    "Surge": ["surge.sh"],
    "ReadMe": ["readme.io"],
    "Pantheon": ["pantheonsite.io"],
    "WP Engine": ["wpengine.com"],
    "Unbounce": ["unbouncepages.com"],
    "Bitbucket": ["bitbucket.io"],
    "Shopify": ["myshopify.com"],
    "Fastly": ["fastly.net", "fastlylb.net"],
}


def fingerprint_provider(value: str) -> str | None:
    lower = value.lower().rstrip(".")
    for provider, markers in PROVIDERS.items():
        if any(marker in lower for marker in markers):
            return provider
    return None


def analyze_takeover_candidates(result: dict) -> dict:
    candidates = []
    records = result.get("records", {})
    for cname in records.get("CNAME", {}).get("values", []) or []:
        provider = fingerprint_provider(cname)
        if provider:
            candidates.append({"asset": result.get("target", {}).get("domain"), "cname": cname, "provider": provider, "confidence": "low", "source": "apex-cname"})
    for item in result.get("subdomains", {}).get("verified_subdomains", []) + result.get("subdomains", {}).get("active", []):
        for cname in item.get("cname", []) or []:
            provider = fingerprint_provider(cname)
            if provider:
                candidates.append({"asset": item.get("name"), "cname": cname, "provider": provider, "confidence": "medium", "source": "subdomain-cname"})
    dedup = {}
    for item in candidates:
        dedup[(item.get("asset"), item.get("cname"))] = item
    return {"enabled": True, "candidates": list(dedup.values()), "count": len(dedup), "note": "Provider fingerprint only. Manually verify ownership/state before reporting exploitable takeover."}
