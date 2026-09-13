"""Build the RAG retrieval eval set: runtime fingerprints -> capability entries.

Gold pairs come from two places:

* ``experiment/result/<domain>-NN.md`` run reports — the target fingerprint is
  taken from the bootstrap service line and the analyze-phase hypotheses, and
  the scenario is identified by the port recorded in the benchmark GUIDE;
* benchmark GUIDEs themselves — for scenarios without a run report the
  fingerprint is the environment/technique description (never the exploitation
  steps), so the query stays a target fingerprint rather than an answer.

Gold labels are the curated capability entries whose ``derived_from`` mentions
the scenario, so the mapping is authored once inside the corpus.

Usage:
    python -m tools.build_rag_eval
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "darwin.rag.eval.v1"

NEGATIVES = [
    ("neg-smtp-relay", "SMTP open relay hardening checklist", "web_db"),
    ("neg-printer-firmware", "printer firmware upgrade procedure", "web_db"),
    ("neg-quantum-physics", "quantum chromodynamics lattice gauge renormalization", "public_cloud"),
    ("neg-hr-onboarding", "employee onboarding policy approval workflow", "web_db"),
    ("neg-weather-api", "public weather forecast API rate limit tiers", "public_cloud"),
    ("neg-bgp-peering", "BGP peering agreement documentation for an ISP backbone", "network"),
    ("neg-mobile-app-release", "mobile app store release checklist", "web_db"),
    ("neg-greenhouse-control", "greenhouse irrigation controller calibration", "web_db"),
    ("neg-payroll-export", "payroll export file schema for finance reporting", "web_db"),
    ("neg-transformer-training", "training a transformer language model on a GPU cluster", "public_cloud"),
    ("neg-library-catalog", "public library catalog search relevance ranking", "web_db"),
    ("neg-traffic-signal", "city traffic signal timing optimization study", "web_db"),
]


def _guide_fields(text: str) -> dict:
    def cell(label: str) -> str:
        match = re.search(r"\|\s*" + label + r"\s*\|\s*(.+?)\s*\|", text)
        return match.group(1).strip() if match else ""

    return {
        "id": cell("ID"),
        "env": cell("环境与访问"),
        "core": cell("核心漏洞与利用"),
        "entry": cell("入口"),
        "tech": cell("技术/CVE"),
    }


def _scenario_capabilities(knowledge_root: Path) -> dict:
    """scenario slug -> curated capability ids (from provenance.derived_from)."""
    mapping: dict = {}
    for path in sorted((knowledge_root / "corpus").glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            if entry.get("provenance", {}).get("kind") != "curated":
                continue
            derived = str(entry["provenance"].get("derived_from") or "")
            prefix = "benchmark scenarios:"
            if prefix not in derived:
                continue
            for slug in derived.split(prefix, 1)[1].split(","):
                slug = slug.strip()
                if slug:
                    mapping.setdefault(slug, []).append(entry["id"])
    return mapping


def _fingerprint_from_report(report: Path, port: str) -> str:
    """Target fingerprint observed during a real run of this scenario."""
    text = report.read_text(encoding="utf-8", errors="replace")
    parts: list = []
    if port:
        for line in text.splitlines():
            if re.search(rf"port {port}/tcp", line):
                parts.append(line.strip()[:160])
                break
    understanding = re.search(r'"application_understanding":\s*"(.{0,300}?)"', text, re.S)
    if understanding:
        parts.append(understanding.group(1).replace("\\n", " ")[:220])
    vuln_types = re.findall(r'"vuln_type":\s*"([^"]+)"', text)
    known = ("weak_auth", "auth_bypass", "idor", "sqli", "ssrf", "cmdi", "lfi",
             "ssti", "xss", "rce", "platform_discovery")
    for vuln_type in dict.fromkeys(vuln_types):
        if any(k in vuln_type.lower().replace(" ", "_") for k in known):
            parts.append(vuln_type)
    return " ".join(parts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(ROOT / "knowledge" / "eval" / "runtime_queries.json"))
    parser.add_argument("--results-dir", default=str(ROOT.parent / "experiment" / "result"))
    parser.add_argument("--benchmark-dir",
                        default=str(ROOT.parent / "benchmark" / "cve_challenges" / "scenarios"))
    args = parser.parse_args(argv)

    knowledge_root = ROOT / "knowledge"
    benchmark_root = Path(args.benchmark_dir)
    scenario_caps = _scenario_capabilities(knowledge_root)
    results_dir = Path(args.results_dir)

    queries: list = []
    for guide in sorted(benchmark_root.rglob("GUIDE.md")):
        domain, slug = guide.parent.parent.name, guide.parent.name
        fields = _guide_fields(guide.read_text(encoding="utf-8", errors="replace"))
        gold = scenario_caps.get(slug, [])
        query = " ".join(x for x in (fields["env"], fields["core"]) if x)
        source = "guide:fingerprint"
        port = re.search(r":(\d{4,5})", fields["entry"] or "")
        # Benchmark GUIDE ids (CLOUD-28) map directly onto result file names.
        report_name = (fields["id"] or "").strip().lower().replace(" ", "")
        report = results_dir / f"{report_name}.md" if report_name else None
        if report and report.is_file():
            fingerprint = _fingerprint_from_report(report, port.group(1) if port else "")
            if fingerprint:
                query = fingerprint
                source = f"run:{report.name}"
        queries.append({
            "id": f"{domain}-{slug}",
            "query": query[:400],
            "scenario": slug,
            "domain": domain,
            "environment": {"cloud": "public_cloud", "k8s": "private_cloud"}.get(domain, "web_db"),
            "gold": gold,
            "source": source,
        })

    negatives = [
        {"id": qid, "query": q, "scenario": "", "domain": "", "environment": env,
         "gold": [], "source": "authored:negative"}
        for qid, q, env in NEGATIVES
    ]

    payload = {
        "schema": SCHEMA,
        "scenario_count": len(queries),
        "covered": sum(1 for q in queries if q["gold"]),
        "queries": queries,
        "negatives": negatives,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}: {len(queries)} scenario queries "
          f"({payload['covered']} with gold), {len(negatives)} negatives")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
