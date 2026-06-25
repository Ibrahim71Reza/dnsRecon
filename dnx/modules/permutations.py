from __future__ import annotations

ENV_TOKENS = ["dev", "test", "stage", "staging", "qa", "uat", "prod", "preprod", "demo", "old", "new"]
REGION_TOKENS = ["us", "eu", "ap", "asia", "sg", "uk", "ca", "au", "in", "bd"]
SERVICE_TOKENS = ["api", "auth", "admin", "portal", "app", "cdn", "static", "assets", "sso", "vpn", "mail"]


def generate_permutations(names: list[str], root_domain: str, *, limit: int = 5000) -> list[str]:
    """Generate conservative DNS name mutations from known subdomains.

    This intentionally avoids aggressive unbounded generation. It is meant to
    enrich authorized recon with practical env/service naming patterns.
    """
    root = root_domain.strip(".").lower()
    output: set[str] = set()
    for name in names:
        clean = name.strip(".").lower()
        if clean == root or not clean.endswith("." + root):
            continue
        left = clean[: -(len(root) + 1)]
        labels = left.split(".")
        if not labels:
            continue
        first = labels[0]
        for token in ENV_TOKENS:
            output.add(f"{token}-{first}.{root}")
            output.add(f"{first}-{token}.{root}")
            output.add(f"{token}.{first}.{root}")
        for token in SERVICE_TOKENS:
            output.add(f"{token}-{first}.{root}")
            output.add(f"{first}-{token}.{root}")
        for token in REGION_TOKENS:
            output.add(f"{first}-{token}.{root}")
        if len(labels) == 1:
            for env in ENV_TOKENS[:6]:
                output.add(f"{first}.{env}.{root}")
        if len(output) >= limit:
            break
    return sorted(output)[:limit]
