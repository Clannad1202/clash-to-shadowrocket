#!/usr/bin/env python3
"""Convert a ShellCrash / Mihomo (Clash) YAML config into Shadowrocket configs & rule sets.

Generates:
  1. dist/rules/<provider>.list      - Shadowrocket-compatible RULE-SET files
  2. dist/shadowrocket.conf          - Modular Shadowrocket config (GitHub Raw URLs)
  3. dist/shadowrocket-cdn.conf      - Modular Shadowrocket config (jsDelivr CDN URLs)
  4. dist/shadowrocket-inline.conf   - Single-file Shadowrocket config with all rules inlined
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

USER_AGENT = "shellcrash-to-shadowrocket/1.0 (+https://github.com)"

# Shadowrocket does not support Clash's PASS policy in [Rule] / [Proxy Group].
POLICY_ALIAS_MAP = {
    "PASS": "DIRECT",
}

SUPPORTED_CLASSICAL_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "DST-PORT",
    "SRC-IP",
    "URL-REGEX",
    "USER-AGENT",
    "PROTOCOL",
    "IP-ASN",
}

CLASSICAL_TYPE_ALIAS = {
    "SRC-IP-CIDR": "SRC-IP",
}

IP_LIKE_TYPES = {"IP-CIDR", "IP-CIDR6", "GEOIP", "IP-ASN"}

SUPPORTED_GROUP_TYPES = {"select", "url-test", "fallback", "load-balance"}

DEFAULT_TEST_URL = "http://www.gstatic.com/generate_204"
DEFAULT_TEST_INTERVAL = 600
DEFAULT_TEST_TIMEOUT = 5

JSDELIVR_GH_RE = re.compile(
    r"^https?://[^/]*jsdelivr\.net/gh/(?P<owner>[^/]+)/(?P<repo>[^/@]+)@(?P<ref>[^/]+)/(?P<path>.+)$"
)
GH_RELEASE_RE = re.compile(
    r"^https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/releases/download/(?P<ref>[^/]+)/(?P<path>.+)$"
)
DOMAIN_VALID_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9\-_.]*[a-z0-9])?$")


@dataclass
class ProviderResult:
    name: str
    behavior: str
    source_url: str
    resolved_url: str
    rules: list[str] = field(default_factory=list)
    skipped: int = 0
    no_resolve_only: bool = False


def load_yaml_file(path: Path) -> dict[str, Any]:
    """Load YAML using PyYAML if installed, falling back to macOS/system Ruby YAML."""
    raw = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(raw)
        if not isinstance(data, dict):
            raise ValueError(f"Expected YAML mapping in {path}")
        return data
    except ModuleNotFoundError:
        pass

    ruby = shutil.which("ruby")
    if ruby:
        proc = subprocess.run(
            [
                ruby,
                "-ryaml",
                "-rjson",
                "-e",
                "puts JSON.generate(YAML.safe_load(ARGF.read, aliases: true))",
                str(path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            data = json.loads(proc.stdout)
            if not isinstance(data, dict):
                raise ValueError(f"Expected YAML mapping in {path}")
            return data
        raise RuntimeError(f"Ruby YAML fallback failed: {proc.stderr.strip()}")

    raise RuntimeError(
        "PyYAML is required to parse config.yaml. Install it via: pip install -r requirements.txt"
    )


def map_policy(policy: str) -> str:
    policy = policy.strip()
    return POLICY_ALIAS_MAP.get(policy.upper(), policy)


def build_candidate_urls(url: str, fmt: str = "") -> list[str]:
    """Generate ordered candidate URLs to fetch text/YAML rules for a provider.

    Mihomo .mrs files are binary; for repositories like DustinWin/ruleset_geodata
    that publish sibling .list text files, try the .list/.yaml/.txt equivalents
    and GitHub raw/release mirrors automatically.
    """
    url = url.strip()
    fmt = fmt.strip().lower()
    candidates: list[str] = []

    def add(u: str) -> None:
        if u and u not in candidates:
            candidates.append(u)

    is_mrs = fmt == "mrs" or url.lower().endswith(".mrs")

    if is_mrs:
        stem = url[:-4] if url.lower().endswith(".mrs") else url
        add(f"{stem}.list")

        m_jsd = JSDELIVR_GH_RE.match(url)
        if m_jsd:
            owner, repo, ref, rel_path = (
                m_jsd.group("owner"),
                m_jsd.group("repo"),
                m_jsd.group("ref"),
                m_jsd.group("path"),
            )
            rel_stem = rel_path[:-4] if rel_path.lower().endswith(".mrs") else rel_path
            filename = Path(rel_stem).name
            add(f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{rel_stem}.list")
            add(f"https://github.com/{owner}/{repo}/releases/download/{ref}/{filename}.list")
            add(f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{rel_stem}.yaml")
            add(f"https://github.com/{owner}/{repo}/releases/download/{ref}/{filename}.yaml")

        m_rel = GH_RELEASE_RE.match(url)
        if m_rel:
            owner, repo, ref, rel_path = (
                m_rel.group("owner"),
                m_rel.group("repo"),
                m_rel.group("ref"),
                m_rel.group("path"),
            )
            rel_stem = rel_path[:-4] if rel_path.lower().endswith(".mrs") else rel_path
            add(f"https://github.com/{owner}/{repo}/releases/download/{ref}/{rel_stem}.list")
            add(f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{rel_stem}.list")
            add(f"https://github.com/{owner}/{repo}/releases/download/{ref}/{rel_stem}.yaml")

        add(f"{stem}.yaml")
        add(f"{stem}.txt")
    else:
        add(url)
        m_jsd = JSDELIVR_GH_RE.match(url)
        if m_jsd:
            owner, repo, ref, rel_path = (
                m_jsd.group("owner"),
                m_jsd.group("repo"),
                m_jsd.group("ref"),
                m_jsd.group("path"),
            )
            add(f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{rel_path}")

    return candidates


def is_valid_text_payload(raw: bytes) -> bool:
    if not raw or b"\x00" in raw:
        return False
    head = raw[:256].lstrip().lower()
    if head.startswith(b"<!doctype html") or head.startswith(b"<html"):
        return False
    return True


def fetch_text(url: str, timeout: int, retries: int) -> str:
    last_err: Exception | None = None
    for attempt in range(1, retries + 1):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                if not is_valid_text_payload(raw):
                    raise ValueError(f"Non-text or HTML response received from {url}")
                return raw.decode("utf-8", errors="strict")
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError) as exc:
            last_err = exc
            if isinstance(exc, urllib.error.HTTPError) and exc.code in (400, 403, 404, 410):
                # Non-transient client error: skip retries and let caller try next mirror.
                break
            if attempt < retries:
                time.sleep(min(2 ** (attempt - 1), 4))
    raise RuntimeError(f"Failed to fetch {url}: {last_err}")


def strip_inline_comment(line: str) -> str:
    """Remove comments (# or // or ;) outside single/double quotes."""
    in_single = False
    in_double = False
    for idx, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double:
            if ch == "#" or ch == ";":
                return line[:idx]
            if ch == "/" and idx + 1 < len(line) and line[idx + 1] == "/":
                return line[:idx]
    return line


def unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and ((text[0] == "'" and text[-1] == "'") or (text[0] == '"' and text[-1] == '"')):
        return text[1:-1].strip()
    return text


def extract_raw_entries(content: str) -> list[str]:
    """Extract rule entries from either Clash YAML (payload:) or plain-text rule lists."""
    entries: list[str] = []
    is_yaml_payload = False

    for raw_line in content.splitlines():
        cleaned = strip_inline_comment(raw_line).strip()
        if not cleaned:
            continue
        if cleaned == "payload:" or cleaned.startswith("payload:"):
            is_yaml_payload = True
            rest = cleaned[len("payload:") :].strip()
            if rest.startswith("[") and rest.endswith("]"):
                for item in rest[1:-1].split(","):
                    val = unquote(item)
                    if val:
                        entries.append(val)
            continue

        if is_yaml_payload:
            if cleaned.startswith("-"):
                val = unquote(cleaned[1:].strip())
                if val:
                    entries.append(val)
            else:
                # Reached another top-level YAML key
                break
        else:
            if cleaned.startswith("- "):
                val = unquote(cleaned[2:].strip())
            else:
                val = unquote(cleaned)
            if val:
                entries.append(val)

    return entries


def convert_classical_entry(entry: str, force_no_resolve: bool = False) -> str | None:
    parts = [p.strip() for p in entry.split(",") if p.strip()]
    if len(parts) < 2:
        return None

    rtype = CLASSICAL_TYPE_ALIAS.get(parts[0].upper(), parts[0].upper())
    if rtype not in SUPPORTED_CLASSICAL_TYPES:
        return None

    value = parts[1]
    if rtype in ("IP-CIDR", "IP-CIDR6"):
        try:
            net = ipaddress.ip_network(value, strict=False)
            rtype = "IP-CIDR" if net.version == 4 else "IP-CIDR6"
            value = net.with_prefixlen
        except ValueError:
            return None
    elif rtype in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"):
        value = value.lower().rstrip(".")
        if not value:
            return None

    has_no_resolve = any(p.lower() == "no-resolve" for p in parts[2:])
    if rtype in IP_LIKE_TYPES and (has_no_resolve or force_no_resolve):
        return f"{rtype},{value},no-resolve"
    return f"{rtype},{value}"


def convert_domain_entry(entry: str) -> str | None:
    """Convert Clash domain-behavior entry to Shadowrocket RULE-SET line."""
    # Some community .list files already contain classical-style DOMAIN lines.
    if "," in entry:
        return convert_classical_entry(entry)

    domain = entry.strip().lower()
    if not domain:
        return None

    is_suffix = False
    if domain.startswith("+."):
        is_suffix = True
        domain = domain[2:]
    elif domain.startswith("*."):
        is_suffix = True
        domain = domain[2:]
    elif domain.startswith("."):
        is_suffix = True
        domain = domain[1:]

    domain = domain.rstrip(".")
    if domain and not domain.isascii():
        try:
            domain = domain.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None
    # Shadowrocket does not support mid-domain wildcards like foo.*.bar.com
    if not domain or "*" in domain or "+" in domain or ".." in domain or not DOMAIN_VALID_RE.match(domain):
        return None

    return f"DOMAIN-SUFFIX,{domain}" if is_suffix else f"DOMAIN,{domain}"


def convert_ipcidr_entry(entry: str, add_no_resolve: bool = False) -> str | None:
    """Convert Clash ipcidr-behavior entry to Shadowrocket IP-CIDR / IP-CIDR6 line."""
    if "," in entry:
        return convert_classical_entry(entry, force_no_resolve=add_no_resolve)

    try:
        net = ipaddress.ip_network(entry.strip(), strict=False)
    except ValueError:
        return None

    rtype = "IP-CIDR" if net.version == 4 else "IP-CIDR6"
    suffix = ",no-resolve" if add_no_resolve else ""
    return f"{rtype},{net.with_prefixlen}{suffix}"


def convert_provider_content(
    content: str,
    behavior: str,
    add_no_resolve: bool = False,
) -> tuple[list[str], int]:
    """Convert raw rule-provider text into deduplicated Shadowrocket RULE-SET lines."""
    behavior = behavior.strip().lower() or "classical"
    raw_entries = extract_raw_entries(content)

    seen: set[str] = set()
    rules: list[str] = []
    skipped = 0

    for entry in raw_entries:
        if behavior == "domain":
            converted = convert_domain_entry(entry)
        elif behavior == "ipcidr":
            converted = convert_ipcidr_entry(entry, add_no_resolve=add_no_resolve)
        else:
            converted = convert_classical_entry(entry, force_no_resolve=add_no_resolve)

        if converted is None:
            skipped += 1
            continue
        if converted not in seen:
            seen.add(converted)
            rules.append(converted)

    return rules, skipped


def analyze_provider_no_resolve(rules: list[str]) -> dict[str, bool]:
    """Determine which providers are exclusively referenced with no-resolve in Clash rules."""
    usages: dict[str, set[bool]] = {}
    for line in rules:
        parts = [p.strip() for p in str(line).split(",")]
        if len(parts) >= 3 and parts[0].upper() == "RULE-SET":
            name = parts[1]
            has_nr = any(p.lower() == "no-resolve" for p in parts[3:])
            usages.setdefault(name, set()).add(has_nr)
    return {name: (flags == {True}) for name, flags in usages.items()}


def fetch_and_convert_provider(
    name: str,
    spec: dict[str, Any],
    add_no_resolve: bool,
    timeout: int,
    retries: int,
    offline_fixtures: Path | None = None,
) -> ProviderResult:
    behavior = str(spec.get("behavior", "classical")).strip().lower()
    fmt = str(spec.get("format", "")).strip().lower()
    url = str(spec.get("url", "")).strip()

    if offline_fixtures is not None:
        for ext in (".list", ".yaml", ".yml", ".txt"):
            candidate = offline_fixtures / f"{name}{ext}"
            if candidate.exists():
                content = candidate.read_text(encoding="utf-8")
                rules, skipped = convert_provider_content(content, behavior, add_no_resolve=add_no_resolve)
                return ProviderResult(
                    name=name,
                    behavior=behavior,
                    source_url=url,
                    resolved_url=str(candidate),
                    rules=rules,
                    skipped=skipped,
                    no_resolve_only=add_no_resolve,
                )
        raise FileNotFoundError(f"Offline fixture for provider '{name}' not found in {offline_fixtures}")

    candidates = build_candidate_urls(url, fmt)
    errors: list[str] = []
    for cand in candidates:
        try:
            content = fetch_text(cand, timeout=timeout, retries=retries)
            rules, skipped = convert_provider_content(content, behavior, add_no_resolve=add_no_resolve)
            if not rules:
                errors.append(f"{cand}: parsed 0 valid rules")
                continue
            return ProviderResult(
                name=name,
                behavior=behavior,
                source_url=url,
                resolved_url=cand,
                rules=rules,
                skipped=skipped,
                no_resolve_only=add_no_resolve,
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{cand}: {exc}")

    detail = "\n  - ".join(errors)
    raise RuntimeError(f"Unable to fetch/convert rule-provider '{name}':\n  - {detail}")


def convert_proxy_groups(proxy_groups: list[dict[str, Any]]) -> list[str]:
    """Convert Clash proxy-groups into Shadowrocket [Proxy Group] lines."""
    lines: list[str] = []
    for group in proxy_groups:
        name = str(group.get("name", "")).strip()
        if not name:
            continue

        gtype = str(group.get("type", "select")).strip().lower()
        if gtype not in SUPPORTED_GROUP_TYPES:
            gtype = "select"

        tokens: list[str] = [gtype]

        raw_proxies = group.get("proxies") or []
        for p in raw_proxies:
            mapped = map_policy(str(p))
            if mapped:
                tokens.append(mapped)

        include_all = bool(group.get("include-all") or group.get("include-all-proxies"))
        regex_filter = str(group.get("filter") or "").strip()
        exclude_filter = str(group.get("exclude-filter") or "").strip()

        if regex_filter and exclude_filter:
            combined_regex = f"(?=.*({regex_filter}))^((?!({exclude_filter})).)*$"
            tokens.append(f"policy-regex-filter={combined_regex}")
        elif regex_filter:
            tokens.append(f"policy-regex-filter={regex_filter}")
        elif exclude_filter:
            tokens.append(f"policy-regex-filter=^((?!({exclude_filter})).)*$")
        elif include_all:
            tokens.append("policy-regex-filter=.*")

        if gtype in ("url-test", "fallback", "load-balance"):
            test_url = str(group.get("url") or DEFAULT_TEST_URL).strip()
            interval = int(group.get("interval") or DEFAULT_TEST_INTERVAL)
            timeout = int(group.get("timeout") or DEFAULT_TEST_TIMEOUT)
            tokens.append(f"url={test_url}")
            tokens.append(f"interval={interval}")
            tokens.append(f"timeout={timeout}")
            if gtype == "url-test" and group.get("tolerance") is not None:
                tokens.append(f"tolerance={int(group['tolerance'])}")

        if group.get("hidden"):
            tokens.append("hidden=1")

        lines.append(f"{name} = {', '.join(tokens)}")

    return lines


def apply_policy_to_rule(rule_line: str, policy: str, force_no_resolve: bool = False) -> str:
    """Turn a Shadowrocket RULE-SET line ('TYPE,VALUE[,no-resolve]') into a full [Rule] line."""
    parts = [p.strip() for p in rule_line.split(",")]
    rtype, value = parts[0], parts[1]
    has_no_resolve = any(p.lower() == "no-resolve" for p in parts[2:])
    if rtype in IP_LIKE_TYPES and (has_no_resolve or force_no_resolve):
        return f"{rtype},{value},{policy},no-resolve"
    return f"{rtype},{value},{policy}"


def convert_rules(
    clash_rules: list[str],
    providers: dict[str, ProviderResult],
    rules_base_url: str | None,
    inline: bool = False,
) -> tuple[list[str], int]:
    """Convert Clash rules list to Shadowrocket [Rule] lines."""
    output: list[str] = []
    skipped = 0

    for raw in clash_rules:
        line = str(raw).strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        rtype = parts[0].upper()

        if rtype == "MATCH" and len(parts) >= 2:
            policy = map_policy(parts[1])
            output.append(f"FINAL,{policy}")
            continue

        if rtype == "RULE-SET" and len(parts) >= 3:
            provider_name = parts[1]
            policy = map_policy(parts[2])
            has_no_resolve = any(p.lower() == "no-resolve" for p in parts[3:])

            if provider_name not in providers:
                raise KeyError(f"Rule references unknown rule-provider '{provider_name}'")

            if inline:
                prov = providers[provider_name]
                output.append(f"# --- RULE-SET: {provider_name} ({len(prov.rules)} rules) ---")
                for r in prov.rules:
                    output.append(apply_policy_to_rule(r, policy, force_no_resolve=has_no_resolve))
            else:
                if not rules_base_url:
                    raise ValueError("rules_base_url is required when inline=False")
                list_url = f"{rules_base_url.rstrip('/')}/{provider_name}.list"
                nr_suffix = ",no-resolve" if has_no_resolve else ""
                output.append(f"RULE-SET,{list_url},{policy}{nr_suffix}")
            continue

        # Direct inline rule inside Clash rules:
        if len(parts) >= 3:
            mapped_type = CLASSICAL_TYPE_ALIAS.get(rtype, rtype)
            if mapped_type in SUPPORTED_CLASSICAL_TYPES:
                value = parts[1]
                policy = map_policy(parts[2])
                has_no_resolve = any(p.lower() == "no-resolve" for p in parts[3:])
                base_rule = convert_classical_entry(f"{mapped_type},{value}", force_no_resolve=has_no_resolve)
                if base_rule:
                    output.append(apply_policy_to_rule(base_rule, policy, force_no_resolve=has_no_resolve))
                    continue

        skipped += 1

    return output, skipped


def render_conf(
    general_text: str,
    proxy_group_lines: list[str],
    rule_lines: list[str],
    managed_url: str | None = None,
    description: str = "",
) -> str:
    sections: list[str] = []
    header_lines: list[str] = []
    if managed_url:
        header_lines.append(f"#!MANAGED-CONFIG {managed_url} interval=86400 strict=false")
    header_lines.append("# Auto-generated from ShellCrash config.yaml for Shadowrocket")
    if description:
        header_lines.append(f"# {description}")
    header_lines.append("# Note: Clash 'PASS' policy is mapped to 'DIRECT' for Shadowrocket compatibility.")
    sections.append("\n".join(header_lines))

    sections.append(general_text.strip())
    sections.append("[Proxy Group]\n" + "\n".join(proxy_group_lines))
    sections.append("[Rule]\n" + "\n".join(rule_lines))
    return "\n\n".join(sections) + "\n"


def render_rule_list(prov: ProviderResult) -> str:
    header = [
        f"# Rule-Set: {prov.name}",
        f"# Behavior: {prov.behavior}",
        f"# Source: {prov.resolved_url}",
        f"# Rules: {len(prov.rules)}",
    ]
    return "\n".join(header) + "\n" + "\n".join(prov.rules) + "\n"


def write_summary(summary_path: Path, providers: dict[str, ProviderResult], generated_files: list[str]) -> None:
    lines = [
        "## ShellCrash -> Shadowrocket Sync Summary",
        "",
        "| Rule-Set | Behavior | Rules | Skipped | Source |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    total_rules = 0
    total_skipped = 0
    for prov in providers.values():
        total_rules += len(prov.rules)
        total_skipped += prov.skipped
        lines.append(
            f"| `{prov.name}` | `{prov.behavior}` | {len(prov.rules):,} | {prov.skipped:,} | `{prov.resolved_url}` |"
        )
    lines.append(f"| **Total** | | **{total_rules:,}** | **{total_skipped:,}** | |")
    lines.append("")
    lines.append("### Generated Files")
    for gf in generated_files:
        lines.append(f"- `{gf}`")
    lines.append("")
    summary_path.write_text("\n".join(lines), encoding="utf-8")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convert ShellCrash Clash YAML to Shadowrocket configs")
    parser.add_argument("--config", type=Path, default=Path("config/config.yaml"), help="Path to ShellCrash config.yaml")
    parser.add_argument(
        "--general", type=Path, default=Path("templates/general.ini"), help="Path to Shadowrocket [General] template"
    )
    parser.add_argument("--output-dir", type=Path, default=Path("dist"), help="Output directory")
    parser.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY", ""),
        help="GitHub repository in 'owner/repo' format (auto-detected in GitHub Actions)",
    )
    parser.add_argument(
        "--branch",
        default=os.environ.get("GITHUB_REF_NAME", "main"),
        help="GitHub branch name (default: main)",
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("RAW_BASE_URL", ""),
        help="Override base URL for dist/ in shadowrocket.conf (e.g. https://raw.githubusercontent.com/user/repo/main/dist)",
    )
    parser.add_argument(
        "--cdn-base-url",
        default=os.environ.get("CDN_BASE_URL", ""),
        help="Override CDN base URL for dist/ in shadowrocket-cdn.conf (e.g. https://testingcf.jsdelivr.net/gh/user/repo@main/dist)",
    )
    parser.add_argument("--timeout", type=int, default=30, help="HTTP request timeout in seconds")
    parser.add_argument("--retries", type=int, default=3, help="HTTP retries per URL")
    parser.add_argument("--workers", type=int, default=6, help="Parallel download workers")
    parser.add_argument("--no-inline", action="store_true", help="Skip generating shadowrocket-inline.conf")
    parser.add_argument("--summary-file", type=Path, default=None, help="Optional Markdown summary output file")
    parser.add_argument(
        "--offline-fixtures",
        type=Path,
        default=None,
        help="Use local rule files from this directory instead of fetching over HTTP",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    config = load_yaml_file(args.config)
    general_text = args.general.read_text(encoding="utf-8")

    proxy_groups = config.get("proxy-groups") or []
    rule_providers_cfg: dict[str, dict[str, Any]] = config.get("rule-providers") or {}
    clash_rules: list[str] = config.get("rules") or []

    no_resolve_map = analyze_provider_no_resolve(clash_rules)

    # Fetch and convert all rule-providers concurrently while preserving original key order.
    provider_results: dict[str, ProviderResult] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        future_to_name = {
            pool.submit(
                fetch_and_convert_provider,
                name,
                spec,
                no_resolve_map.get(name, False),
                args.timeout,
                args.retries,
                args.offline_fixtures,
            ): name
            for name, spec in rule_providers_cfg.items()
        }
        tmp_results: dict[str, ProviderResult] = {}
        for fut in concurrent.futures.as_completed(future_to_name):
            name = future_to_name[fut]
            res = fut.result()
            tmp_results[name] = res
            print(
                f"[OK] {name:14s} ({res.behavior:9s}): {len(res.rules):6d} rules "
                f"(skipped {res.skipped}) <- {res.resolved_url}"
            )

    for name in rule_providers_cfg:
        provider_results[name] = tmp_results[name]

    # Prepare output directories
    out_dir: Path = args.output_dir
    rules_dir = out_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)

    # Clean stale .list files that are no longer in config.yaml
    expected_files = {f"{name}.list" for name in provider_results}
    for existing in rules_dir.glob("*.list"):
        if existing.name not in expected_files:
            existing.unlink()

    generated_files: list[str] = []
    for name, prov in provider_results.items():
        list_path = rules_dir / f"{name}.list"
        list_path.write_text(render_rule_list(prov), encoding="utf-8")
        generated_files.append(str(list_path))

    proxy_group_lines = convert_proxy_groups(proxy_groups)

    # Compute dist base URLs
    repo = args.repo.strip()
    branch = args.branch.strip() or "main"
    dist_name = out_dir.name

    raw_dist_base = args.base_url.strip().rstrip("/")
    if not raw_dist_base:
        if repo:
            raw_dist_base = f"https://raw.githubusercontent.com/{repo}/{branch}/{dist_name}"
        else:
            raw_dist_base = f"https://raw.githubusercontent.com/<YOUR_USER>/<YOUR_REPO>/{branch}/{dist_name}"

    cdn_dist_base = args.cdn_base_url.strip().rstrip("/")
    if not cdn_dist_base:
        if repo:
            cdn_dist_base = f"https://testingcf.jsdelivr.net/gh/{repo}@{branch}/{dist_name}"
        else:
            cdn_dist_base = f"https://testingcf.jsdelivr.net/gh/<YOUR_USER>/<YOUR_REPO>@{branch}/{dist_name}"

    # 1. Modular GitHub Raw config
    raw_rules, raw_skipped = convert_rules(
        clash_rules, provider_results, rules_base_url=f"{raw_dist_base}/rules", inline=False
    )
    raw_conf_path = out_dir / "shadowrocket.conf"
    raw_conf_path.write_text(
        render_conf(
            general_text,
            proxy_group_lines,
            raw_rules,
            managed_url=f"{raw_dist_base}/shadowrocket.conf" if repo or args.base_url else None,
            description="Modular config using GitHub Raw RULE-SET URLs",
        ),
        encoding="utf-8",
    )
    generated_files.append(str(raw_conf_path))

    # 2. Modular jsDelivr CDN config
    cdn_rules, _ = convert_rules(
        clash_rules, provider_results, rules_base_url=f"{cdn_dist_base}/rules", inline=False
    )
    cdn_conf_path = out_dir / "shadowrocket-cdn.conf"
    cdn_conf_path.write_text(
        render_conf(
            general_text,
            proxy_group_lines,
            cdn_rules,
            managed_url=f"{cdn_dist_base}/shadowrocket-cdn.conf" if repo or args.cdn_base_url else None,
            description="Modular config using jsDelivr CDN (testingcf.jsdelivr.net) RULE-SET URLs",
        ),
        encoding="utf-8",
    )
    generated_files.append(str(cdn_conf_path))

    # 3. Single-file inline config
    if not args.no_inline:
        inline_rules, _ = convert_rules(clash_rules, provider_results, rules_base_url=None, inline=True)
        inline_conf_path = out_dir / "shadowrocket-inline.conf"
        inline_conf_path.write_text(
            render_conf(
                general_text,
                proxy_group_lines,
                inline_rules,
                managed_url=f"{cdn_dist_base}/shadowrocket-inline.conf" if repo or args.cdn_base_url else None,
                description="Single-file self-contained config with all rules inlined",
            ),
            encoding="utf-8",
        )
        generated_files.append(str(inline_conf_path))

    if args.summary_file:
        write_summary(args.summary_file, provider_results, generated_files)

    print(
        f"\nDone! Converted {len(provider_results)} rule-sets "
        f"({sum(len(p.rules) for p in provider_results.values()):,} total rules, "
        f"{raw_skipped} unsupported top-level rules skipped)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
