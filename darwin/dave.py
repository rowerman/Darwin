"""Defense-Aware Verification Engine — four-layer exploit verification.

Reference:
  - AWE xss_agent/agents/verifier.py — Playwright browser verification
  - PACEBench flag validation — flag format matching
  - CyberGym PoC validation — exit code based verification
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse


class VerifyStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    BLOCKED_BY_WAF = "blocked_by_waf"
    MODIFIED = "modified"
    UNKNOWN = "unknown"


@dataclass
class LayerResult:
    """Single verification layer result."""
    layer: int
    status: VerifyStatus
    confidence: float
    detail: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VerificationResult:
    """Aggregated verification result from all layers."""
    passed: bool
    status: VerifyStatus
    confidence: float
    layer_results: List[LayerResult] = field(default_factory=list)
    flag_value: str = ""
    flag_location: str = ""
    is_honeypot_flag: bool = False
    defense_detected: bool = False
    defense_type: str = ""
    notes: List[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        parts = [f"PASS={self.passed}", f"confidence={self.confidence:.2f}"]
        if self.flag_value:
            parts.append(f"flag={self.flag_value}")
        if self.is_honeypot_flag:
            parts.append("HONEYPOT_FLAG")
        if self.defense_detected:
            parts.append(f"defense={self.defense_type}")
        return " | ".join(parts)


class DAVE:
    """Defense-Aware Verification Engine.

    L1: HTTP Response verification (status codes, response size, timing)
    L2: Browser-side verification (Playwright - JavaScript execution)
    L3: Defense Integrity verification (payload sent vs reflected comparison)
    L4: Impact Confirmation (flag extraction and honeypot detection)
    """

    FLAG_PATTERN = re.compile(r"flag\{[a-zA-Z0-9_\-!@#$%^&*()+=]+\}", re.IGNORECASE)

    # Honey flag patterns
    HONEY_FLAG_PATTERNS = [
        re.compile(r"flag\{this_is_a_honeypot\}", re.IGNORECASE),
        re.compile(r"flag\{test\}", re.IGNORECASE),
        re.compile(r"flag\{example\}", re.IGNORECASE),
        re.compile(r"flag\{sample\}", re.IGNORECASE),
        re.compile(r"flag\{congratulations_fake\}", re.IGNORECASE),
        re.compile(r"flag\{fake_flag\}", re.IGNORECASE),
        re.compile(r"flag\{you_win\}", re.IGNORECASE),
    ]

    def __init__(self, browser_enabled: bool = False):
        self.browser_enabled = browser_enabled
        self._browser = None

    async def verify(
        self,
        exploit_attempt: ExploitAttempt,
        probe_results: List[Any] | None = None,
    ) -> VerificationResult:
        """Run full 4-layer verification.

        Args:
            exploit_attempt: Details of the exploitation attempt
            probe_results: Optional filter probe results for L3 comparison

        Returns:
            VerificationResult with pass/fail and detailed layer results
        """
        layer_results = []
        notes = []

        # L1: HTTP Response verification
        l1 = self._verify_http(exploit_attempt)
        layer_results.append(l1)
        if l1.status == VerifyStatus.BLOCKED_BY_WAF:
            return VerificationResult(
                passed=False, status=VerifyStatus.BLOCKED_BY_WAF,
                confidence=l1.confidence, layer_results=layer_results,
                defense_detected=True, defense_type="waf",
                notes=["L1: Payload blocked by WAF"],
            )

        # L2: Browser verification (if applicable)
        if self.browser_enabled and exploit_attempt.vuln_type in ("XSS", "DOM_XSS"):
            l2 = await self._verify_browser(exploit_attempt)
            layer_results.append(l2)

        # L3: Defense Integrity verification
        if probe_results:
            l3 = self._verify_defense_integrity(exploit_attempt, probe_results)
            layer_results.append(l3)
            if l3.status == VerifyStatus.MODIFIED:
                notes.append("L3: Payload modified by defense")
                return VerificationResult(
                    passed=False, status=VerifyStatus.MODIFIED,
                    confidence=l3.confidence, layer_results=layer_results,
                    defense_detected=True, defense_type="waf_or_filter",
                    notes=notes,
                )

        # L4: Impact Confirmation (flag extraction)
        l4 = self._verify_impact(exploit_attempt)
        layer_results.append(l4)

        passed = l4.status == VerifyStatus.PASS
        flag_value = l4.evidence.get("flag_value", "")
        is_honeypot = l4.evidence.get("is_honeypot_flag", False)

        # Overall confidence = average of non-skipped layers
        confidences = [r.confidence for r in layer_results if r.confidence > 0]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

        return VerificationResult(
            passed=passed,
            status=l4.status,
            confidence=avg_confidence,
            layer_results=layer_results,
            flag_value=flag_value,
            flag_location=l4.evidence.get("flag_location", ""),
            is_honeypot_flag=is_honeypot,
            defense_detected=any(
                r.status in (VerifyStatus.BLOCKED_BY_WAF, VerifyStatus.MODIFIED)
                for r in layer_results
            ),
            notes=notes,
        )

    # ── Layer 1: HTTP Response ──────────────────────────────────────

    def _verify_http(self, attempt: ExploitAttempt) -> LayerResult:
        """Verify based on HTTP response characteristics."""
        resp = attempt.http_response
        if resp is None:
            return LayerResult(1, VerifyStatus.FAIL, 0.0, "No HTTP response")

        # Check for WAF blocking
        if resp.status_code in (403, 406, 429, 493, 999):
            return LayerResult(
                1, VerifyStatus.BLOCKED_BY_WAF, 0.8,
                f"Blocked with status {resp.status_code}",
                evidence={"status_code": resp.status_code},
            )

        # Check for unusual response body
        if len(resp.body) == 0:
            return LayerResult(1, VerifyStatus.FAIL, 0.5, "Empty response body")

        body_lower = resp.body.lower()
        block_indicators = ["blocked", "forbidden", "access denied", "request rejected"]
        for indicator in block_indicators:
            if indicator in body_lower:
                return LayerResult(
                    1, VerifyStatus.BLOCKED_BY_WAF, 0.7,
                    f"Block indicator in body: '{indicator}'",
                )

        # Check response timing
        if resp.elapsed_ms > 10000:
            return LayerResult(
                1, VerifyStatus.FAIL, 0.3, f"Response too slow: {resp.elapsed_ms:.0f}ms",
            )

        return LayerResult(1, VerifyStatus.PASS, 0.9, f"HTTP {resp.status_code}")

    # ── Layer 2: Browser Verification ────────────────────────────────

    async def _verify_browser(self, attempt: ExploitAttempt) -> LayerResult:
        """Verify using headless browser (XSS-specific).

        Reference: AWE xss_agent/agents/verifier.py
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return LayerResult(2, VerifyStatus.UNKNOWN, 0.0, "Playwright not installed")

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()

            js_executed = False
            dialog_triggered = False

            async def handle_dialog(dialog):
                nonlocal dialog_triggered
                dialog_triggered = True
                await dialog.dismiss()

            page.on("dialog", handle_dialog)

            try:
                await page.goto(attempt.target_url, timeout=10000)
                await page.wait_for_timeout(2000)

                # Check if JavaScript executed
                try:
                    result = await page.evaluate("() => typeof window._xss_triggered !== 'undefined'")
                    if result:
                        js_executed = True
                except Exception as e:
                    import logging
                    logging.getLogger(__name__).warning(
                        "DAVE._verify_browser: JavaScript evaluation failed: %s", e
                    )

                if dialog_triggered or js_executed:
                    return LayerResult(
                        2, VerifyStatus.PASS, 0.95,
                        "JavaScript executed in browser",
                        evidence={"dialog_triggered": dialog_triggered, "js_executed": js_executed},
                    )

                return LayerResult(
                    2, VerifyStatus.FAIL, 0.3,
                    "No JavaScript execution observed",
                )
            except Exception as e:
                return LayerResult(2, VerifyStatus.FAIL, 0.2, f"Browser error: {e}")
            finally:
                await browser.close()

    # ── Layer 3: Defense Integrity ───────────────────────────────────

    def _verify_defense_integrity(
        self, attempt: ExploitAttempt, probe_results: List[Any]
    ) -> LayerResult:
        """Verify that the payload was not modified by a defense mechanism.

        Reference: AWE ContextAnalyzer — reflection analysis
        """
        sent = attempt.payload or ""
        if not sent:
            return LayerResult(3, VerifyStatus.UNKNOWN, 0.0, "No payload to verify")

        # Check if payload appears in response (possibly modified)
        reflected = ""
        resp_body = attempt.http_response.body if attempt.http_response else ""

        if sent in resp_body:
            reflected = sent
            return LayerResult(
                3, VerifyStatus.PASS, 0.95,
                "Payload reflected intact",
                evidence={"sent": sent, "reflected": reflected},
            )

        # Check for HTML-encoded version
        import html
        encoded = html.escape(sent)
        if encoded != sent and encoded in resp_body:
            return LayerResult(
                3, VerifyStatus.MODIFIED, 0.7,
                "Payload HTML-encoded by defense",
                evidence={"sent": sent, "reflected": encoded, "modification": "html_encode"},
            )

        # Check probe results for modification patterns
        for probe in probe_results:
            if probe.modified and probe.probe_value in sent:
                return LayerResult(
                    3, VerifyStatus.MODIFIED, 0.6,
                    f"Payload modified: {probe.probe_value} → {probe.reflected_value}",
                    evidence={"modification_type": probe.probe_class},
                )

        return LayerResult(3, VerifyStatus.UNKNOWN, 0.3, "Payload not found in response")

    # ── Layer 4: Impact Confirmation ─────────────────────────────────

    def _verify_impact(self, attempt: ExploitAttempt) -> LayerResult:
        """Verify actual impact — flag extraction and honeypot detection."""
        # Extract flags from response and stdout
        all_text = ""
        if attempt.http_response:
            all_text += attempt.http_response.body
        if attempt.tool_stdout:
            all_text += "\n" + attempt.tool_stdout

        flags = self.FLAG_PATTERN.findall(all_text)

        if not flags:
            return LayerResult(
                4, VerifyStatus.FAIL, 0.0,
                "No flag found in response or tool output",
            )

        # Check for honeypot flags
        for flag in flags:
            for honeypot_pat in self.HONEY_FLAG_PATTERNS:
                if honeypot_pat.match(flag):
                    return LayerResult(
                        4, VerifyStatus.FAIL, 0.1,
                        f"Honeypot flag detected: {flag}",
                        evidence={"flag_value": flag, "is_honeypot_flag": True},
                    )

        # First non-honeypot flag
        flag = flags[0]
        location = "http_response" if flag in (attempt.http_response.body if attempt.http_response else "") else "tool_stdout"

        return LayerResult(
            4, VerifyStatus.PASS, 0.9,
            f"Flag captured: {flag}",
            evidence={
                "flag_value": flag,
                "flag_location": location,
                "is_honeypot_flag": False,
                "all_flags": flags,
            },
        )


@dataclass
class ExploitAttempt:
    """Container for an exploitation attempt's details."""
    target_url: str
    vuln_type: str = ""
    payload: str = ""
    http_response: Any = None  # HTTPResponse
    tool_stdout: str = ""
    tool_stderr: str = ""
    steps: List[Dict] = field(default_factory=list)
