"""Defense Perception Module — detect and classify target defenses.

Reference:
  - AWE xss_agent/analyzers/filter_detector.py — probe-based filter detection
  - CHeaT cheat/database/ — 33 defense techniques in JSON
  - CPA classifier/hybrid.go — rule + LLM hybrid classifier pattern
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from darwin.prompts.dpm_classifier import DPM_CLASSIFIER_PROMPT

# WAF fingerprint database path (relative to project root)
_WAF_DB_PATH = Path(__file__).parent.parent / "config" / "waf_fingerprints.yaml"


class DefenseCategory(str, Enum):
    NONE = "none"
    WAF = "waf"
    CLOAK = "cloak"
    HONEY = "honey"
    TRAP = "trap"
    COMBINED = "combined"


class SanitizationStrategy(str, Enum):
    NONE = "none"
    BLACKLIST = "blacklist"
    WHITELIST = "whitelist"
    OUTPUT_ENCODING = "output_encoding"
    HYBRID = "hybrid"
    UNKNOWN = "unknown"


@dataclass
class FilterProfile:
    """Result of filter behavior analysis from probes."""
    blocked_chars: List[str] = field(default_factory=list)
    encoded_chars: Dict[str, str] = field(default_factory=dict)  # char -> encoded_form
    blocked_tags: List[str] = field(default_factory=list)
    blocked_events: List[str] = field(default_factory=list)
    blocked_protocols: List[str] = field(default_factory=list)
    strategy: SanitizationStrategy = SanitizationStrategy.UNKNOWN
    strictness: float = 0.0  # 0.0-1.0
    encoding_behavior: str = "unknown"  # none | pass_through | decode_then_filter | decode_only


@dataclass
class WAFMatch:
    """Result of WAF signature matching."""
    waf_id: str = ""
    waf_family: str = ""
    confidence: float = 0.0
    matched_rules: List[str] = field(default_factory=list)
    bypass_hints: List[str] = field(default_factory=list)


@dataclass
class DefenseCategoryScores:
    """Confidence scores for each defense category."""
    waf: float = 0.0
    cloak: float = 0.0
    honey: float = 0.0
    trap: float = 0.0
    none: float = 1.0

    @property
    def primary(self) -> DefenseCategory:
        best = max(
            [("waf", self.waf), ("cloak", self.cloak),
             ("honey", self.honey), ("trap", self.trap), ("none", self.none)],
            key=lambda x: x[1],
        )
        if best[0] == "none":
            return DefenseCategory.NONE
        return DefenseCategory(best[0])


@dataclass
class DefenseStateVector:
    """Complete defense state assessment.

    Reference: DARWIN framework spec — D = [waf_type, waf_confidence,
    sanitization_strategy, sanitization_strictness, defense_category,
    defense_complexity, bypass_progress]
    """
    waf_type: str = "unknown"
    waf_confidence: float = 0.0
    sanitization_strategy: SanitizationStrategy = SanitizationStrategy.UNKNOWN
    sanitization_strictness: float = 0.0
    defense_category: DefenseCategory = DefenseCategory.NONE
    defense_category_scores: DefenseCategoryScores = field(default_factory=DefenseCategoryScores)
    defense_complexity: float = 0.0  # D value in TDI''
    bypass_attempts: int = 0
    bypass_successes: int = 0
    attempted_strategies: List[str] = field(default_factory=list)
    observation_count: int = 0
    honeypot_count: int = 0
    cloak_detected: bool = False
    waf_match: Optional[WAFMatch] = None
    filter_profile: Optional[FilterProfile] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "waf_type": self.waf_type,
            "waf_confidence": self.waf_confidence,
            "sanitization_strategy": self.sanitization_strategy.value,
            "sanitization_strictness": self.sanitization_strictness,
            "defense_category": self.defense_category.value,
            "defense_complexity": self.defense_complexity,
            "bypass_attempts": self.bypass_attempts,
            "bypass_successes": self.bypass_successes,
        }

    def to_query_text(self) -> str:
        """Generate text for CTEG similarity query."""
        parts = [
            f"WAF: {self.waf_type}({self.waf_confidence:.2f})",
            f"Filter: {self.sanitization_strategy.value}({self.sanitization_strictness:.2f})",
            f"Defense: {self.defense_category.value}",
        ]
        return " ".join(parts)


class DefensePerceptionModule:
    """Defense perception module with hybrid detection.

    Layer 1: FilterDetector (rule-based probe analysis, 0 LLM cost)
    Layer 2: WAF Signature Match (rule-based, 0 LLM cost)
    Layer 3: LLM Classifier (triggered only when confidence < 0.8)

    Reference: CPA classifier/hybrid.go:24-60 — rule + LLM hybrid
    """

    # Honey indicator patterns
    HONEY_INDICATORS = [
        (r"flag\{this_is_a_honeypot\}", 0.3),
        (r"flag\{test\}", 0.25),
        (r"flag\{congratulations_fake\}", 0.3),
        (r"flag\{example\}", 0.2),
        (r"flag\{sample\}", 0.2),
        (r"passwords\.txt.*fake|decoy|honeypot", 0.35),
        (r"admin:admin|root:root|test:test", 0.2),
    ]

    # Trap indicator patterns
    TRAP_INDICATORS = [
        (r"(?i)(ignore.*previous.*instruction|system.*message.*:)", 0.35),
        (r"(?i)(stop.*testing|submit.*flag.*and.*stop|this.*system.*has.*been.*patched)", 0.4),
    ]

    def __init__(self, llm_session=None, waf_db_path: str | None = None):
        self._llm = llm_session
        self._waf_signatures: List[Dict] = []
        self._load_waf_signatures(waf_db_path)

    def _load_waf_signatures(self, path: str | None = None):
        """Load WAF fingerprint database from YAML or JSON."""
        if path is None:
            path = str(_WAF_DB_PATH)
        if not os.path.exists(path):
            return

        if path.endswith(".yaml") or path.endswith(".yml"):
            try:
                import yaml
                with open(path) as f:
                    data = yaml.safe_load(f)
                self._waf_signatures = data.get("wafs", [])
            except ImportError:
                import logging
                logging.getLogger(__name__).warning(
                    "DPM: PyYAML not installed, cannot load WAF fingerprint database from %s", path
                )
        elif path.endswith(".json"):
            with open(path) as f:
                data = json.load(f)
            self._waf_signatures = data.get("wafs", [])

    def detect(
        self,
        probe_results: List[Any],  # List[ProbeResult]
        http_responses: List[Any],  # List[HTTPResponse]
        use_llm: bool = True,
    ) -> DefenseStateVector:
        """Run full defense detection pipeline.

        Args:
            probe_results: Filter probe results from ProbeClient
            http_responses: Raw HTTP responses from interactions
            use_llm: Whether to use LLM classifier for low-confidence cases

        Returns:
            DefenseStateVector with complete defense assessment
        """
        # Stage 1: Filter behavior analysis (0 LLM cost)
        filter_profile = self._analyze_filter_behavior(probe_results)

        # Stage 2: WAF signature matching (0 LLM cost)
        waf_match = self._match_waf_signatures(http_responses)

        # Stage 3: Defense taxonomy classification
        category_scores = self._classify_defense_category(http_responses, filter_profile)

        # Build defense state vector
        dsv = DefenseStateVector(
            waf_type=waf_match.waf_id or "unknown",
            waf_confidence=waf_match.confidence,
            sanitization_strategy=filter_profile.strategy,
            sanitization_strictness=filter_profile.strictness,
            defense_category=category_scores.primary,
            defense_category_scores=category_scores,
            waf_match=waf_match,
            filter_profile=filter_profile,
        )

        # Compute defense complexity (D value)
        dsv.defense_complexity = self._compute_defense_complexity(dsv)

        # Stage 4 (optional): LLM classifier for low-confidence cases
        if use_llm and self._llm and self._overall_confidence(dsv) < 0.8:
            dsv = self._llm_classify(dsv, probe_results, http_responses)

        dsv.observation_count = 1
        return dsv

    def _analyze_filter_behavior(self, probe_results: List[Any]) -> FilterProfile:
        """Analyze probe results to build filter profile.

        Reference: AWE xss_agent/analyzers/filter_detector.py
        """
        profile = FilterProfile()

        if not probe_results:
            return profile

        for probe in probe_results:
            pv = probe.probe_value
            pc = probe.probe_class

            if probe.blocked:
                if pc == "A":
                    profile.blocked_chars.append(pv)
                elif pc == "B":
                    profile.blocked_tags.append(pv)
                elif pc == "C":
                    profile.blocked_events.append(pv)
                elif pc == "D":
                    profile.blocked_protocols.append(pv)
            elif probe.modified and probe.reflected_value:
                if pc == "A":
                    profile.encoded_chars[pv] = probe.reflected_value

        # Classify strategy
        n_blocked = len(profile.blocked_chars)
        n_encoded = len(profile.encoded_chars)

        if n_blocked == 0 and n_encoded == 0:
            profile.strategy = SanitizationStrategy.NONE
            profile.strictness = 0.0
        elif n_encoded > n_blocked:
            profile.strategy = SanitizationStrategy.OUTPUT_ENCODING
            profile.strictness = 0.5
        elif n_blocked > 0 and n_encoded == 0:
            profile.strategy = SanitizationStrategy.BLACKLIST
            profile.strictness = min(n_blocked / 10.0, 1.0)
        else:
            profile.strategy = SanitizationStrategy.HYBRID
            profile.strictness = min((n_blocked + n_encoded) / 10.0, 1.0)

        # Determine encoding behavior from Class E probes
        e_probes = [p for p in probe_results if p.probe_class == "E"]
        if e_probes:
            if all(p.blocked for p in e_probes):
                profile.encoding_behavior = "decode_then_filter"
            elif any(p.modified for p in e_probes):
                profile.encoding_behavior = "decode_only"
            elif any(not p.blocked for p in e_probes):
                profile.encoding_behavior = "pass_through"

        return profile

    def _match_waf_signatures(self, http_responses: List[Any]) -> WAFMatch:
        """Match responses against known WAF signatures.

        Reference: CHeaT cheat/database/ defense technique patterns
        """
        best_match = WAFMatch()

        for waf in self._waf_signatures:
            matched_rules = []
            total_weight = 0.0

            for rule in waf.get("rules", []):
                rule_type = rule.get("type")
                rule_conf = rule.get("confidence", 0.5)

                if rule_type == "response_header":
                    field = rule.get("field", "")
                    pattern = rule.get("pattern", "")
                    for resp in http_responses:
                        header_val = resp.headers.get(field, "")
                        if header_val and re.search(pattern, header_val):
                            matched_rules.append(f"header:{field}")
                            total_weight += rule_conf
                            break

                elif rule_type == "response_body":
                    pattern = rule.get("pattern", "")
                    for resp in http_responses:
                        if re.search(pattern, resp.body):
                            matched_rules.append("body_match")
                            total_weight += rule_conf
                            break

                elif rule_type == "block_page":
                    for block_pattern in rule.get("patterns", []):
                        for resp in http_responses:
                            if block_pattern in resp.body:
                                matched_rules.append(f"block:{block_pattern[:30]}")
                                total_weight += rule_conf
                                break

                elif rule_type == "status_code":
                    expected = rule.get("value")
                    for resp in http_responses:
                        if resp.status_code == expected:
                            matched_rules.append(f"status:{expected}")
                            total_weight += rule_conf
                            break

            if matched_rules:
                confidence = min(total_weight / len(waf.get("rules", [1])), 1.0)
                if confidence > best_match.confidence:
                    best_match = WAFMatch(
                        waf_id=waf.get("id", ""),
                        waf_family=waf.get("family", ""),
                        confidence=confidence,
                        matched_rules=matched_rules,
                        bypass_hints=waf.get("bypass_hints", []),
                    )

        return best_match

    def _classify_defense_category(
        self, http_responses: List[Any], filter_profile: FilterProfile
    ) -> DefenseCategoryScores:
        """Classify defense into Cloak/Honey/Trap/WAF categories.

        Reference: CHeaT cheat/database/ + Proactive_Defenses taxonomy
        """
        scores = DefenseCategoryScores()

        # Cloak indicators: port anomaly, banner inconsistency, response confusion
        cloaked = 0.0
        for resp in http_responses:
            if resp.status_code == 404 and "robots.txt" not in resp.url:
                # might be a cloaked response
                cloaked += 0.1
            if resp.elapsed_ms > 3000:
                cloaked += 0.1
        scores.cloak = min(cloaked, 1.0)

        # Honey indicators: too-easy vulnerabilities, fake flags, obvious creds
        honey_score = 0.0
        for resp in http_responses:
            for pattern, weight in self.HONEY_INDICATORS:
                if re.search(pattern, resp.body, re.IGNORECASE):
                    honey_score += weight
        scores.honey = min(honey_score, 1.0)

        # Trap indicators: infinite responses, semantic confusion, adversarial prompts
        trap_score = 0.0
        for resp in http_responses:
            for pattern, weight in self.TRAP_INDICATORS:
                if re.search(pattern, resp.body, re.IGNORECASE):
                    trap_score += weight
            if resp.elapsed_ms > 10000:  # very slow response
                trap_score += 0.15
        scores.trap = min(trap_score, 1.0)

        # WAF indicator from filter profile
        if filter_profile.strategy != SanitizationStrategy.NONE:
            scores.waf = 0.5

        # If nothing detected, "none" = 1.0, others = 0
        all_scores = [scores.cloak, scores.honey, scores.trap, scores.waf]
        if max(all_scores) < 0.15:
            scores.none = 1.0
            scores.cloak = scores.honey = scores.trap = scores.waf = 0.0
        else:
            scores.none = 0.0

        return scores

    def _compute_defense_complexity(self, dsv: DefenseStateVector) -> float:
        """Compute D (Defense Complexity) for TDI'' formula.

        D = 0.4 * D_waf + 0.3 * D_filter + 0.3 * D_deception
        """
        # WAF complexity
        D_waf = dsv.waf_confidence * self._waf_difficulty_score(dsv.waf_type)

        # Filter complexity
        if dsv.sanitization_strategy in (
            SanitizationStrategy.WHITELIST,
            SanitizationStrategy.OUTPUT_ENCODING,
        ):
            D_filter = dsv.sanitization_strictness * 1.0
        elif dsv.sanitization_strategy == SanitizationStrategy.BLACKLIST:
            D_filter = dsv.sanitization_strictness * 0.5
        else:
            D_filter = 0.0

        # Deception complexity
        scores = dsv.defense_category_scores
        D_deception = 0.5 * max(scores.cloak, scores.honey) + 0.5 * scores.trap

        return 0.4 * D_waf + 0.3 * D_filter + 0.3 * D_deception

    @staticmethod
    def _waf_difficulty_score(waf_type: str) -> float:
        """Map WAF type to bypass difficulty."""
        mapping = {
            "unknown": 0.0,
            "": 0.0,
            "coraza": 0.6,
            "modsecurity_crs": 0.6,
            "naxsi": 0.7,
            "cloudflare": 0.9,
        }
        return mapping.get(waf_type, 0.5)

    def _overall_confidence(self, dsv: DefenseStateVector) -> float:
        """Compute overall confidence in defense assessment."""
        if dsv.defense_category == DefenseCategory.NONE:
            return 0.9
        components = [dsv.waf_confidence]
        if dsv.filter_profile:
            components.append(dsv.filter_profile.strictness)
        if components:
            return sum(components) / len(components)
        return 0.3

    def _llm_classify(
        self,
        dsv: DefenseStateVector,
        probe_results: List[Any],
        http_responses: List[Any],
    ) -> DefenseStateVector:
        """Use LLM to re-classify defense when rule confidence is low.

        Reference: CPA classifier/hybrid.go — LLM fallback classifier
        """
        if not self._llm:
            return dsv

        prompt = self._build_classifier_prompt(dsv, probe_results, http_responses)
        content, _ = self._llm.generate(prompt, temperature=0.1)

        # Parse LLM output for defense type and confidence
        try:
            result = json.loads(content)
            dsv.waf_type = result.get("waf_type", dsv.waf_type)
            dsv.waf_confidence = max(dsv.waf_confidence, result.get("waf_confidence", 0))
            if "defense_category" in result:
                dsv.defense_category = DefenseCategory(result["defense_category"])
            dsv.observation_count += 1
        except (json.JSONDecodeError, ValueError):
            pass  # keep rule-based result

        return dsv

    def _build_classifier_prompt(
        self, dsv: DefenseStateVector, probes: List[Any], responses: List[Any]
    ) -> str:
        """Build prompt for LLM defense classifier using the template from darwin.prompts."""
        resp_summary = []
        for r in responses[-5:]:  # last 5 responses
            resp_summary.append(
                f"  {r.url}: status={r.status_code}, "
                f"len={len(r.body)}, time={r.elapsed_ms:.0f}ms"
            )

        probe_summary = []
        for p in probes[-10:]:
            probe_summary.append(
                f"  {p.probe_value}: blocked={p.blocked}, modified={p.modified}"
            )

        return DPM_CLASSIFIER_PROMPT.format(
            http_responses="\n".join(resp_summary) if resp_summary else "(none)",
            probe_results="\n".join(probe_summary) if probe_summary else "(none)",
            waf_type=dsv.waf_type or "unknown",
            waf_confidence=f"{dsv.waf_confidence:.2f}",
            sanitization_strategy=dsv.sanitization_strategy.value,
            sanitization_strictness=f"{dsv.sanitization_strictness:.2f}",
        )
