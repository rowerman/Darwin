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
    """Async HTTP client for penetration testing interactions.

    Maintains cookies across requests via a shared CookieJar, enabling
    authenticated session-based scanning.
    """

    def __init__(self, timeout: int = 10):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self._session: Optional[aiohttp.ClientSession] = None
        self._cookie_jar = aiohttp.CookieJar()
        self._baselines: Dict[str, BaselineResult] = {}

    async def _ensure_session(self):
        if self._session is None:
            self._session = aiohttp.ClientSession(
                timeout=self.timeout, cookie_jar=self._cookie_jar,
            )

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
        json_data: Dict | None = None, headers: Dict[str, str] | None = None,
        allow_redirects: bool = True,
    ) -> HTTPResponse:
        """Send POST request."""
        await self._ensure_session()
        start = time.perf_counter()
        async with self._session.post(
            url, data=data, json=json_data, headers=headers or {},
            allow_redirects=allow_redirects,
        ) as resp:
            body = await resp.text()
            elapsed = (time.perf_counter() - start) * 1000
            return HTTPResponse(
                url=str(resp.url),
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

    async def auto_login(
        self, url: str, username: str, password: str,
    ) -> bool:
        """Attempt automatic login to a web application.

        Detects login forms by looking for password inputs, then tries
        common username/password field names. Supports both direct POST
        and multi-step (username → password) login flows.

        Returns True if login appeared successful (redirect, session cookie).
        """
        import logging as _logging
        _log = _logging.getLogger(__name__)

        base = url.rstrip("/")
        login_urls = [base, f"{base}/login", f"{base}/signin"]

        # Record pre-login cookie count to detect genuine new cookies
        pre_cookies = 0
        if self._session and self._session.cookie_jar:
            pre_cookies = len(list(self._session.cookie_jar))

        login_success = False
        for login_url in login_urls:
            try:
                resp = await self.get(login_url)
            except Exception:
                continue

            body = resp.body
            # Detect login form: must have username OR password field
            # (two-step login may have only username on first page)
            bl = body.lower()
            if "password" not in bl and "username" not in bl:
                continue

            _log.info("Login form detected at %s", login_url)

            # Extract form: find <form> action, method, and all <input> fields
            import re as _re
            # Match form attributes in any order
            action_m = _re.search(r'''action=["']([^"']*)["']''', body, _re.I)
            method_m = _re.search(r'''method=["'](\w+)["']''', body, _re.I)
            action = action_m.group(1) if action_m else ""
            method = (method_m.group(1) or "post").upper() if method_m else "POST"

            # Build the submission URL
            from urllib.parse import urljoin as _urljoin
            submit_url = _urljoin(login_url, action) if action else login_url

            # Find all input fields
            inputs = _re.findall(
                r'<input[^>]+name=["\'](\w+)["\']', body, _re.I
            )
            input_types = dict(_re.findall(
                r'<input[^>]+name=["\'](\w+)["\'][^>]+type=["\'](\w+)["\']', body, _re.I
            ))

            # Detect field roles
            user_field = "username"
            pass_field = "password"
            for name in inputs:
                nl = name.lower()
                if nl in ("username", "user", "email", "login", "uname"):
                    user_field = name
                elif nl in ("password", "pass", "passwd", "pwd"):
                    pass_field = name

            # Try direct login (username + password in one form)
            form_data = {user_field: username, pass_field: password}
            # Include hidden fields
            hidden = _re.findall(
                r'<input[^>]+type=["\']hidden["\'][^>]+name=["\'](\w+)["\'][^>]+value=["\']([^"\']*)["\']', body, _re.I
            )
            for h_name, h_value in hidden:
                form_data[h_name] = h_value
            # Include CSRF tokens
            csrf = _re.search(
                r'<input[^>]+name=["\']([^"\']*csrf[^"\']*)["\'][^>]+value=["\']([^"\']*)["\']', body, _re.I
            )
            if csrf:
                form_data[csrf.group(1)] = csrf.group(2)

            try:
                if method == "POST":
                    login_resp = await self.post(submit_url, data=form_data)
                else:
                    qs = "&".join(f"{k}={v}" for k, v in form_data.items())
                    login_resp = await self.get(f"{submit_url}?{qs}")
            except Exception:
                continue

            # Check if login succeeded
            post_cookies_1 = len(list(self._session.cookie_jar)) if self._session and self._session.cookie_jar else 0
            if login_resp.status_code in (302, 301, 303, 307, 308):
                _log.info("Login redirect to %s (status=%d)",
                         login_resp.headers.get("location", "?"), login_resp.status_code)
                redirect_url = _urljoin(submit_url, login_resp.headers.get("location", ""))
                try:
                    await self.get(redirect_url)
                except Exception:
                    pass
                login_success = True
                break
            elif "set-cookie" in str(login_resp.headers).lower():
                _log.info("Login Set-Cookie after POST (status=%d)", login_resp.status_code)
                login_success = True
                break
            elif post_cookies_1 > pre_cookies:
                _log.info("Login: %d new cookies after POST", post_cookies_1 - pre_cookies)
                login_success = True
                break

            # Check for multi-step login (username page → password page)
            new_body = login_resp.body
            nl_body = new_body.lower()
            # Did the original form have a password field?
            orig_has_pw = 'type="password"' in body.lower() or "type='password'" in body.lower()
            # Does the response contain a password field?
            resp_has_pw = 'type="password"' in nl_body or "type='password'" in nl_body
            if resp_has_pw and not orig_has_pw:
                # Multi-step login: username-only form → password form
                # Collect ALL input fields from the password page (username,
                # password, hidden CSRF tokens, user_id, etc.)
                pw_inputs = _re.findall(
                    r'<input[^>]+name=["\'](\w+)["\']', new_body, _re.I
                )
                # Also find input values (for hidden/prefilled fields)
                input_vals = dict(_re.findall(
                    r'<input[^>]+name=["\'](\w+)["\'][^>]+value=["\']([^"\']*)["\']',
                    new_body, _re.I
                ))
                pw_data = {user_field: username}  # re-submit username
                for name in pw_inputs:
                    nl = name.lower()
                    if nl in ("password", "pass", "passwd", "pwd"):
                        pw_data[name] = password
                    elif nl != user_field.lower():
                        # Include all other fields with their values (hidden tokens, etc.)
                        if name in input_vals and name not in pw_data:
                            pw_data[name] = input_vals[name]

                if any(nl in ("password", "pass") for nl in [n.lower() for n in pw_inputs]):
                    pw_submit_url = (
                        str(login_resp.url) if hasattr(login_resp, 'url') and login_resp.url
                        else submit_url
                    )
                    try:
                        pw_resp = await self.post(pw_submit_url, data=pw_data)
                        # Success: redirect OR Set-Cookie header OR new cookies
                        post_cookies = len(list(self._session.cookie_jar)) if self._session and self._session.cookie_jar else 0
                        if pw_resp.status_code in (302, 301, 303, 307, 308):
                            redirect_url = _urljoin(submit_url, pw_resp.headers.get("location", ""))
                            try:
                                await self.get(redirect_url)
                            except Exception:
                                pass
                            login_success = True
                            break
                        elif "set-cookie" in str(pw_resp.headers).lower():
                            _log.info("Login Set-Cookie detected after password submission")
                            login_success = True
                            break
                        elif post_cookies > pre_cookies:
                            _log.info("Login: %d new cookies after password submission",
                                     post_cookies - pre_cookies)
                            login_success = True
                            break
                    except Exception:
                        pass

        # After for loop: check if we succeeded (redirect OR genuine new cookies)
        if login_success:
            return True
        if self._session and self._session.cookie_jar:
            jar_cookies = list(self._session.cookie_jar)
            new_cookies = len(jar_cookies) - pre_cookies
            if new_cookies > 0:
                _log.info("Login appears successful (%d new cookies in jar)", new_cookies)
                return True

        return False


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
