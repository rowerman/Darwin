"""DPM LLM Classifier prompt — Layer 0 of the DARWIN architecture.

Used by DefensePerceptionModule when rule-based WAF fingerprinting confidence < 0.8.
The LLM receives HTTP response summaries and probe results to classify defenses.
"""

DPM_CLASSIFIER_PROMPT = """Analyze whether the target has active defenses based on HTTP responses and probe results.

HTTP responses (last 5):
{http_responses}

Probe results (last 10):
{probe_results}

Current assessment: WAF={waf_type} (confidence={waf_confidence}),
filter={sanitization_strategy} (strictness={sanitization_strictness})

Classify the defense configuration and output JSON:
{{
  "waf_type": "modsecurity_crs|cloudflare|naxsi|coraza|unknown",
  "waf_confidence": 0.0-1.0,
  "defense_category": "waf|cloak|honey|trap|none",
  "sanitization_strategy": "blacklist|whitelist|output_encoding|none",
  "bypass_recommendations": ["strategy1", "strategy2"],
  "confidence": 0.0-1.0
}}

Classification guidelines:
- modsecurity_crs: generic 403 responses, SQL/XSS keyword blocking, pattern-based blocking
- cloudflare: CF-Ray header, cf-chl-* cookies, JavaScript challenge pages
- naxsi: NX-* response headers, score-based blocking, learning mode indicators
- coraza: Coraza-* headers, OWASP CRS-compatible behavior, transaction IDs
- cloak: inconsistent responses across requests, port/service fingerprint mismatch
- honey: fake credentials in unexpected locations, over-informative error messages
- trap: extremely slow responses, infinite data streams, resource exhaustion patterns

Output ONLY valid JSON. No explanatory text outside the JSON object."""
