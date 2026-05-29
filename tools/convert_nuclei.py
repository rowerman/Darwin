#!/usr/bin/env python3
"""Convert nuclei-templates CVE YAML files to DARWIN knowledge JSON format.

Usage:
    python tools/convert_nuclei.py --source /tmp/nuclei-templates --output /tmp/nuclei_knowledge
    python tools/ingest_knowledge.py --dir /tmp/nuclei_knowledge --collection web
"""

import argparse
import json
import os
import re
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML required: pip install pyyaml")
    exit(1)

# Tag → DARWIN category mapping
TAG_CATEGORY = {
    "wordpress": ("web", "CMS", "WordPress"),
    "wp-plugin": ("web", "CMS", "WordPress Plugin"),
    "joomla": ("web", "CMS", "Joomla"),
    "drupal": ("web", "CMS", "Drupal"),
    "cve": ("web", "CVE", "RCE"),
    "rce": ("web", "CVE", "RCE"),
    "sqli": ("web", "SQLI", "Web"),
    "sql-injection": ("web", "SQLI", "Web"),
    "xss": ("web", "XSS", "Web"),
    "lfi": ("web", "LFI", "Web"),
    "file-upload": ("web", "UPLOAD", "Web"),
    "ssrf": ("web", "SSRF", "Web"),
    "ssti": ("web", "SSTI", "Web"),
    "cmdi": ("web", "CMDI", "Web"),
    "php": ("web", "CVE", "PHP"),
    "apache": ("web", "CVE", "Apache"),
    "tomcat": ("web", "CVE", "Tomcat"),
    "nginx": ("web", "CVE", "Nginx"),
    "iis": ("web", "CVE", "IIS"),
    "kubernetes": ("cloud", "CVE", "Kubernetes"),
    "k8s": ("cloud", "CVE", "Kubernetes"),
    "docker": ("cloud", "CVE", "Docker"),
    "ad": ("windows_ad", "CVE", "Active Directory"),
    "windows": ("windows_ad", "CVE", "Windows"),
    "smb": ("windows_ad", "CVE", "SMB"),
    "ldap": ("windows_ad", "CVE", "LDAP"),
    "kerberos": ("windows_ad", "CVE", "Kerberos"),
    "intrusive": ("web", "CVE", "Intrusive"),
    "vuln": ("web", "CVE", "General"),
    "exposure": ("web", "EXPOSURE", "General"),
    "misconfig": ("web", "MISCONFIG", "General"),
    "default-login": ("web", "AUTH", "Default Credentials"),
}


def _classify(info: dict, tags: list) -> tuple[str, str, str]:
    """Map nuclei tags to DARWIN (collection, category, subcategory)."""
    for tag in tags:
        tag_lower = tag.lower().replace("_", "-")
        if tag_lower in TAG_CATEGORY:
            return TAG_CATEGORY[tag_lower]
    # Fallback: check description for keywords
    desc = (info.get("description", "") or "").lower()
    if "wordpress" in desc:
        return ("web", "CMS", "WordPress")
    if "kubernetes" in desc or "kubelet" in desc:
        return ("cloud", "CVE", "Kubernetes")
    if "active directory" in desc or "kerberos" in desc:
        return ("windows_ad", "CVE", "Active Directory")
    return ("web", "CVE", "General")


def _extract_http_techniques(http_blocks: list) -> list[str]:
    """Extract HTTP request lines as techniques."""
    techniques = []
    for block in http_blocks:
        if isinstance(block, dict) and "raw" in block:
            raw = block["raw"]
            if isinstance(raw, list):
                raw = "\n".join(raw)
            lines = raw.strip().split("\n")
            for line in lines:
                line = line.strip()
                if line and not line.startswith(("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")):
                    if "Host:" in line or "Content-Type:" in line:
                        continue
                if line:
                    techniques.append(line[:200])
    return techniques[:10]


def _extract_references(info: dict) -> list[str]:
    """Extract reference URLs."""
    refs = []
    for r in info.get("reference", []):
        if isinstance(r, str):
            refs.append(r)
    return refs


def convert_file(yaml_path: Path) -> list[dict]:
    """Convert a single nuclei YAML template to DARWIN entries."""
    with open(yaml_path, encoding="utf-8") as f:
        try:
            data = yaml.safe_load(f)
        except Exception:
            return []

    if not isinstance(data, dict) or "id" not in data:
        return []

    info = data.get("info", {})
    if not info:
        return []

    template_id = data["id"]
    name = info.get("name", template_id)
    severity = info.get("severity", "unknown")
    description = info.get("description", "") or ""
    classification = info.get("classification") or {}
    tags = []
    raw_tags = data.get("tags")
    if isinstance(raw_tags, str):
        tags = [t.strip() for t in raw_tags.split(",")]
    elif isinstance(raw_tags, list):
        tags = raw_tags
    http_blocks = data.get("http")
    if not isinstance(http_blocks, list):
        http_blocks = [http_blocks] if http_blocks else []

    collection, category, subcategory = _classify(info, tags)

    cve_id = classification.get("cve-id", "") or ""
    cvss_score = classification.get("cvss-score", 0)
    cvss_metrics = classification.get("cvss-metrics", "")
    cwe_id = classification.get("cwe-id", "")

    refs = _extract_references(info)
    techniques = _extract_http_techniques(http_blocks if isinstance(http_blocks, list) else [http_blocks])

    return [{
        "id": f"nuclei-{template_id}",
        "title": name,
        "category": category,
        "subcategory": subcategory,
        "description": description[:800].replace("\n", " ").strip(),
        "techniques": techniques,
        "indicators": [],
        "tags": tags,
        "tools": [],
        "prerequisites": [],
        "confidence": _severity_to_confidence(severity),
        "mitre_attack": cwe_id,
        "references": refs,
        "_cve_id": cve_id,
        "_cvss_score": cvss_score,
        "_severity": severity,
    }]


def _severity_to_confidence(sev: str) -> float:
    return {"critical": 0.95, "high": 0.85, "medium": 0.65, "low": 0.4, "info": 0.25}.get(
        sev.lower(), 0.5)


def walk_cve_templates(source_dir: Path) -> list[Path]:
    """Find all CVE YAML files, prioritizing CVE directories."""
    cve_dirs = [
        source_dir / "http" / "cves",
        source_dir / "http" / "cnvd",
        source_dir / "http" / "vulnerabilities",
        source_dir / "http" / "exposures",
        source_dir / "http" / "misconfiguration",
        source_dir / "http" / "default-logins",
    ]
    files = []
    for d in cve_dirs:
        if d.exists():
            files.extend(sorted(d.rglob("*.yaml")))

    # Also include WordPress-specific templates
    wp_dir = source_dir / "http" / "wordpress"
    if wp_dir.exists():
        files.extend(sorted(wp_dir.rglob("*.yaml")))

    # CMS templates
    cms_dir = source_dir / "http" / "cms"
    if cms_dir.exists():
        files.extend(sorted(cms_dir.rglob("*.yaml")))

    return files


def main():
    parser = argparse.ArgumentParser(description="Convert nuclei-templates to DARWIN knowledge JSON")
    parser.add_argument("--source", required=True, help="Path to nuclei-templates repo")
    parser.add_argument("--output", required=True, help="Output directory for JSON files")
    parser.add_argument("--limit", type=int, default=0,
                        help="Max files to convert (0=all)")
    parser.add_argument("--by-collection", action="store_true",
                        help="Split output by collection (web/windows_ad/cloud)")
    args = parser.parse_args()

    source = Path(args.source)
    if not source.exists():
        print(f"Source not found: {source}")
        exit(1)

    files = walk_cve_templates(source)
    print(f"Found {len(files)} CVE templates")

    if args.limit:
        files = files[:args.limit]
        print(f"Limited to {len(files)} files")

    entries_by_coll: dict[str, list] = {}
    total = 0
    for fpath in files:
        entries = convert_file(fpath)
        if entries:
            for e in entries:
                coll = e.pop("collection", "web")
                # Store extra fields that aren't in DARWIN schema
                extra = {}
                for ek in ("_cve_id", "_cvss_score", "_severity"):
                    if ek in e:
                        extra[ek] = e.pop(ek)
                # Put extra fields under description append
                if extra:
                    cve_line = f" [{extra.get('_severity','?')}]"
                    if extra.get("_cve_id"):
                        cve_line += f" CVE:{extra['_cve_id']}"
                    if extra.get("_cvss_score"):
                        cve_line += f" CVSS:{extra['_cvss_score']}"
                    e["description"] = e.get("description", "") + cve_line
                entries_by_coll.setdefault(coll, []).append(e)
                total += 1

    os.makedirs(args.output, exist_ok=True)

    # Output as one merged file per collection
    for coll, entries in entries_by_coll.items():
        out_file = Path(args.output) / f"nuclei-{coll}.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(entries, f, indent=2, ensure_ascii=False)
        print(f"  {coll}: {len(entries)} entries → {out_file}")

    print(f"Total: {total} entries across {len(entries_by_coll)} collections")


if __name__ == "__main__":
    main()
