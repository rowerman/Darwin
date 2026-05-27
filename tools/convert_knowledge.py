#!/usr/bin/env python3
"""Convert external security knowledge (PayloadsAllTheThings, HackTricks, etc.)
into DARWIN knowledge JSON format for batch ingestion.

Usage:
    # Clone sources first
    git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git /tmp/PayloadsAllTheThings
    git clone https://github.com/HackTricks-wiki/hacktricks.git /tmp/hacktricks

    # Convert a directory
    python tools/convert_knowledge.py --source /tmp/PayloadsAllTheThings --output /tmp/darwin_knowledge --category web

    # Ingest the result
    python tools/ingest_knowledge.py --dir /tmp/darwin_knowledge --collection web
"""

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

# Category mapping: PayloadsAllTheThings directory → DARWIN category + subcategory
DIR_CATEGORY_MAP: Dict[str, tuple] = {
    # Web vulns
    "sql injection": ("web", "SQLI"),
    "sql_injection": ("web", "SQLI"),
    "xss injection": ("web", "XSS"),
    "xss_injection": ("web", "XSS"),
    "command injection": ("web", "CMDI"),
    "command_injection": ("web", "CMDI"),
    "file inclusion": ("web", "LFI"),
    "file_inclusion": ("web", "LFI"),
    "ssti": ("web", "SSTI"),
    "ssrf": ("web", "SSRF"),
    "csrf": ("web", "CSRF"),
    "idor": ("web", "IDOR"),
    "jwt": ("web", "AUTH"),
    "oauth": ("web", "AUTH"),
    "xxe": ("web", "XXE"),
    "cors": ("web", "CORS"),
    "deserialization": ("web", "DESERIALIZATION"),
    "upload": ("web", "UPLOAD"),
    "captcha": ("web", "AUTH"),
    "race condition": ("web", "RACE"),
    "race_condition": ("web", "RACE"),
    "web sockets": ("web", "WEBSOCKET"),
    "websocket": ("web", "WEBSOCKET"),
    "http": ("web", "HTTP"),
    # Auth
    "brute force": ("web", "AUTH"),
    "brute_force": ("web", "AUTH"),
    "2fa": ("web", "AUTH"),
    "mfa": ("web", "AUTH"),
    # Infrastructure
    "docker": ("cloud", "CONTAINER"),
    "kubernetes": ("cloud", "K8S"),
    "k8s": ("cloud", "K8S"),
    "aws": ("cloud", "AWS"),
    "gcp": ("cloud", "GCP"),
    "azure": ("cloud", "AZURE"),
    # Network
    "smb": ("network", "SMB"),
    "rdp": ("network", "RDP"),
    "ssh": ("network", "SSH"),
    "dns": ("network", "DNS"),
    "snmp": ("network", "SNMP"),
    # Windows/AD
    "active directory": ("windows_ad", "AD_ENUM"),
    "active_directory": ("windows_ad", "AD_ENUM"),
    "kerberos": ("windows_ad", "KERBEROS"),
    "ntlm": ("windows_ad", "NTLM"),
    "powershell": ("windows_ad", "EXECUTION"),
    # Privilege escalation
    "linux": ("network", "PRIVESC"),
    "windows": ("windows_ad", "PRIVESC"),
    # Persistence
    "persistence": ("windows_ad", "PERSISTENCE"),
    # Lateral movement
    "lateral": ("windows_ad", "LATERAL"),
    "pivoting": ("network", "LATERAL"),
    "tunneling": ("network", "LATERAL"),
    # Methodology
    "methodology": ("web", "RECON"),
    "recon": ("web", "RECON"),
    "enumeration": ("web", "RECON"),
    "discovery": ("web", "RECON"),
    # WAF / Bypass
    "waf": ("web", "BYPASS"),
    "bypass": ("web", "BYPASS"),
    # API
    "api": ("web", "API"),
    "graphql": ("web", "API"),
    # Cloud
    "cloud": ("cloud", "CLOUD"),
    "serverless": ("cloud", "SERVERLESS"),
}


def guess_category(filepath: Path, source_dir: Path, default_category: str) -> tuple:
    """Infer (collection, subcategory) from file path."""
    rel = str(filepath.relative_to(source_dir)).lower()
    for keyword, (cat, subcat) in DIR_CATEGORY_MAP.items():
        if keyword in rel:
            return (cat, subcat)
    return (default_category, "GENERAL")


def extract_title_and_content(filepath: Path) -> tuple:
    """Extract title and clean content from a markdown file."""
    text = filepath.read_text(encoding="utf-8", errors="replace")

    # Extract title from first heading
    title = filepath.stem.replace("_", " ").replace("-", " ")
    for line in text.split("\n"):
        line = line.strip()
        if line.startswith("# "):
            title = line[2:].strip()
            break

    # Remove YAML frontmatter
    if text.startswith("---"):
        parts = text.split("---", 2)
        text = parts[-1] if len(parts) >= 3 else text

    # Clean markdown artifacts
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)  # HTML comments
    text = re.sub(r"\{#[^}]*\}", "", text)  # Hugo shortcodes
    text = re.sub(r"\{\{[^}]*\}\}", "", text)  # Jekyll shortcodes
    text = re.sub(r"\[!\[.*?\]\(.*?\)\]\(.*?\)", "", text)  # Image links
    text = re.sub(r"<[^>]+>", "", text)  # HTML tags

    # Extract techniques from bullet points (skip TOC links)
    techniques = []
    for line in text.split("\n"):
        line = line.strip()
        # Skip markdown TOC links, empty bullets, and section references
        if re.match(r"^\* \[.*\]\(.*\)", line):  # TOC link
            continue
        if re.match(r"^- \[.*\]\(.*\)", line):   # TOC link
            continue
        if re.match(r"^[-*] \*\*", line):  # Bold start - likely a section header
            tech = re.sub(r"\*\*([^*]+)\*\*", r"\1", line[2:]).strip()
            if len(tech) > 5:
                techniques.append(tech)
            continue
        if line.startswith("- ") or line.startswith("* "):
            tech = line[2:].strip()
            # Skip section reference links
            if tech.startswith("[") and "]" in tech:
                continue
            if len(tech) > 10 and len(tech) < 400:
                techniques.append(tech)

    # Extract code blocks as techniques (real payloads)
    code_blocks = re.findall(
        r"```(?:sql|bash|sh|python|powershell|cmd|php|javascript|json|text)?\s*\n(.*?)```",
        text, re.DOTALL | re.IGNORECASE)
    for block in code_blocks[:10]:
        for line in block.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("//"):
                if 5 < len(line) < 300:
                    techniques.append(line)

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for t in techniques:
        key = t[:80].lower()
        if key not in seen:
            seen.add(key)
            unique.append(t)

    return title, text, unique[:30]


def convert_directory(source: str, output: str, default_category: str,
                      max_per_file: int = 200) -> int:
    """Convert all markdown files in source to DARWIN knowledge JSON.

    Returns total number of entries created.
    """
    source_dir = Path(source)
    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    all_entries: List[Dict[str, Any]] = []
    file_count = 0
    skipped_count = 0

    for fpath in sorted(source_dir.rglob("*.md")):
        if fpath.name.startswith(".") or fpath.name == "README.md":
            continue
        if "node_modules" in str(fpath) or ".git" in str(fpath):
            continue

        try:
            title, content, techniques = extract_title_and_content(fpath)
        except Exception:
            skipped_count += 1
            continue

        # Skip files without meaningful content
        if len(content) < 100:
            skipped_count += 1
            continue

        collection, subcategory = guess_category(fpath, source_dir, default_category)
        file_count += 1

        entry_id = f"{subcategory.lower()}-{file_count}"

        # Build description from first meaningful paragraph
        desc_lines = []
        for line in content.split("\n"):
            line = line.strip()
            if line and not line.startswith("#") and len(line) > 30:
                desc_lines.append(line)
                if len(" ".join(desc_lines)) > 500:
                    break
        description = " ".join(desc_lines)[:800]

        all_entries.append({
            "id": entry_id,
            "type": "ExploitPattern",
            "category": subcategory,
            "title": title,
            "description": description,
            "techniques": techniques[:20],
            "indicators": [],
            "tags": [collection, subcategory.lower()],
            "confidence": 0.5,
            "source_file": str(fpath.relative_to(source_dir)),
        })

    # Write entries in batches by collection
    batches: Dict[str, List[Dict]] = {}
    for entry in all_entries:
        coll = entry["tags"][0]
        batches.setdefault(coll, []).append(entry)

    for coll, entries in batches.items():
        for i in range(0, len(entries), max_per_file):
            batch = entries[i:i + max_per_file]
            batch_num = i // max_per_file + 1
            suffix = f"-{batch_num}" if len(entries) > max_per_file else ""
            out_file = output_dir / f"{coll}_converted{suffix}.json"
            # Strip internal fields before writing
            clean = [{k: v for k, v in e.items() if k != "source_file"} for e in batch]
            out_file.write_text(json.dumps(clean, indent=2, ensure_ascii=False))

    print(f"Converted {file_count} files → {len(all_entries)} entries in {len(batches)} collections")
    print(f"Skipped {skipped_count} files (too short or unreadable)")
    print(f"Output: {output_dir}/")
    for f in sorted(output_dir.glob("*.json")):
        print(f"  {f.name} ({len(json.loads(f.read_text()))} entries)")

    return len(all_entries)


def main():
    parser = argparse.ArgumentParser(
        description="Convert external security knowledge to DARWIN format")
    parser.add_argument("--source", required=True,
                        help="Root directory of cloned knowledge repo")
    parser.add_argument("--output", default="/tmp/darwin_knowledge",
                        help="Output directory for JSON files")
    parser.add_argument("--category", default="web",
                        help="Default DARWIN collection (web, cloud, network, windows_ad)")
    parser.add_argument("--max-per-file", type=int, default=200,
                        help="Max entries per output JSON file")
    args = parser.parse_args()

    total = convert_directory(args.source, args.output, args.category, args.max_per_file)
    print(f"\nDone. To ingest:")
    print(f"  python tools/ingest_knowledge.py --dir {args.output}")


if __name__ == "__main__":
    main()
