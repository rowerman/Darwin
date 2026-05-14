"""HTTP client with WAF probe support.

Reference: AWE xss_agent/analyzers/filter_detector.py — probe-based filter detection
           CHeaT cheat/database/ — defense technique patterns
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse, parse_qs

import aiohttp


@dataclass
class HTTPResponse:
    """Structured HTTP response."""
    url: str
    status_code: int
    headers: Dict[str, str]
    body: str
    elapsed_ms: float


@dataclass
class ProbeResult:
    """Result of a single WAF/defense probe."""
    probe_id: str
    probe_class: str  # A (char), B (tag), C (event), D (protocol), E (encoding)
    probe_value: str
    sent_url: str
    sent_param: str
    response: HTTPResponse
    blocked: bool = False
    modified: bool = False
    reflected_value: str = ""
    notes: str = ""


@dataclass
class BaselineResult:
    """Baseline response for comparison."""
    url: str
    response: HTTPResponse
    timestamp: float


class HTTPClient:
    """Async HTTP client for penetration testing interactions."""

    def __init__(self, timeout: int = 10):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self._session: Optional[aiohttp.ClientSession] = None
        self._baselines: Dict[str, BaselineResult] = {}

    async def _ensure_session(self):
        if self._session is None:
            self._session = aiohttp.ClientSession(timeout=self.timeout)

    async def close(self):
        if self._session:
            await self._session.close()
            self._session = None

    async def get(self, url: str, headers: Dict[str, str] | None = None) -> HTTPResponse:
        """Send GET request."""
        await self._ensure_session()
        start = time.perf_counter()
        async with self._session.get(url, headers=headers or {}) as resp:
            body = await resp.text()
            elapsed = (time.perf_counter() - start) * 1000
            return HTTPResponse(
                url=url,
                status_code=resp.status,
                headers=dict(resp.headers),
                body=body,
                elapsed_ms=elapsed,
            )

    async def post(
        self, url: str, data: Dict[str, str] | None = None,
        json_data: Dict | None = None, headers: Dict[str, str] | None = None
    ) -> HTTPResponse:
        """Send POST request."""
        await self._ensure_session()
        start = time.perf_counter()
        async with self._session.post(
            url, data=data, json=json_data, headers=headers or {}
        ) as resp:
            body = await resp.text()
            elapsed = (time.perf_counter() - start) * 1000
            return HTTPResponse(
                url=url,
                status_code=resp.status,
                headers=dict(resp.headers),
                body=body,
                elapsed_ms=elapsed,
            )

    async def get_baseline(self, url: str) -> HTTPResponse:
        """Get a baseline response for a URL (normal request, no probes)."""
        response = await self.get(url)
        self._baselines[url] = BaselineResult(url=url, response=response, timestamp=time.time())
        return response


class ProbeClient(HTTPClient):
    """Client for sending WAF/defense probes.

    Reference: AWE xss_agent/analyzers/filter_detector.py
               — 5 classes of probes: A(char-level), B(tag-level), C(event), D(protocol), E(encoding)
    """

    # Probe sequences (reference: AWE FilterDetector)
    PROBE_CLASSES = {
        "A": [  # Character-level filter probes
            "<", ">", '"', "'", ";", "(", ")", "--", "/*", "|", "`",
        ],
        "B": [  # Tag-level filter probes
            "<script>", "<img>", "<svg>", "<iframe>", "<a>",
            "<scr<script>ipt>",  # recursive tag handling test
        ],
        "C": [  # Event handler filter probes
            "onerror=", "onload=", "onclick=", "onmouseover=", "onfocus=",
        ],
        "D": [  # Protocol/URL filter probes
            "javascript:", "data:", "vbscript:", "http://evil.com",
        ],
        "E": [  # Encoding behavior probes
            "%3C",   # URL-encoded <
            "&lt;",   # HTML entity <
            "\\x3C",  # Hex escape
            "&#60;",  # HTML numeric entity
        ],
    }

    async def send_probe(
        self, url: str, param: str, probe_value: str,
        probe_class: str = "A", method: str = "GET"
    ) -> ProbeResult:
        """Send a single probe and analyze the response."""
        if method.upper() == "GET":
            separator = "&" if "?" in url else "?"
            probe_url = f"{url}{separator}{param}={probe_value}"
            response = await self.get(probe_url)
        else:
            response = await self.post(url, data={param: probe_value})

        # Determine if the probe was blocked
        blocked, modified, reflected = self._analyze_response(
            probe_value, response, url
        )

        return ProbeResult(
            probe_id=f"{probe_class}-{probe_value}",
            probe_class=probe_class,
            probe_value=probe_value,
            sent_url=probe_url if method.upper() == "GET" else url,
            sent_param=param,
            response=response,
            blocked=blocked,
            modified=modified,
            reflected_value=reflected,
            notes="blocked" if blocked else ("modified" if modified else "passed"),
        )

    async def send_probe_batch(
        self, url: str, param: str, probes: List[str],
        probe_class: str = "A", method: str = "GET"
    ) -> List[ProbeResult]:
        """Send a batch of probes sequentially."""
        results = []
        for probe in probes:
            result = await self.send_probe(url, param, probe, probe_class, method)
            results.append(result)
            await asyncio.sleep(0.1)  # avoid rate limiting
        return results

    async def send_all_probe_classes(
        self, url: str, param: str, method: str = "GET"
    ) -> List[ProbeResult]:
        """Send all probe classes (A through E) against a target."""
        all_results = []
        for cls_name, probes in self.PROBE_CLASSES.items():
            results = await self.send_probe_batch(url, param, probes, cls_name, method)
            all_results.extend(results)
        return all_results

    def _analyze_response(
        self, probe_value: str, response: HTTPResponse, baseline_url: str
    ) -> tuple[bool, bool, str]:
        """Analyze whether a probe was blocked or modified.

        Returns:
            (blocked: bool, modified: bool, reflected_value: str)
        """
        blocked = False
        modified = False
        reflected = ""

        # Check for blocking indicators
        if response.status_code in (403, 406, 429, 493, 999, 1020):
            blocked = True
        elif response.elapsed_ms > 5000:  # significant delay
            blocked = True

        # Check for WAF block page patterns
        block_patterns = [
            r"blocked", r"forbidden", r"access denied", r"mod.security",
            r"naxsi", r"cloudflare", r"attention required",
        ]
        for pattern in block_patterns:
            if re.search(pattern, response.body, re.IGNORECASE):
                blocked = True
                break

        # Look for reflected value
        if probe_value in response.body:
            reflected = probe_value
        else:
            # Check for encoded/transformed versions
            import html
            encoded = html.escape(probe_value)
            if encoded != probe_value and encoded in response.body:
                reflected = encoded
                modified = True

        # Check for significant body size reduction (possible content filtering)
        baseline = self._baselines.get(baseline_url)
        if baseline and baseline.response.body:
            baseline_len = len(baseline.response.body)
            response_len = len(response.body)
            if response_len < baseline_len * 0.2:  # >80% reduction
                blocked = True

        return blocked, modified, reflected
