"""Tests for compression protection (O3) and thought-log compatibility (O4.2).

Verifies:
    - MemoryManager.compression_payload() prepends the belief snapshot to
      the preserved payload when a provider is wired (O3.1).
    - LLMSession.compress() routes [COGNITION SNAPSHOT]-marked messages
      verbatim into the preserved context and keeps them out of the
      summarizer's input (O3.2).
    - Hard truncation keeps marked messages instead of dropping them (O3.2).
    - The compression summarizer call still emits a stage="compress"
      thought-log event (O4.2).
"""

import json
import os
from types import SimpleNamespace

import pytest

from darwin.core.belief import SNAPSHOT_MARKER
from darwin.core.memory import ExecutionMemory, MemoryManager
from darwin.tools.mcp_gateway import ToolResult
from darwin.utils.llm import LLMSession


def _fake_completion(content="summary"):
    def _completion(**kwargs):
        message = SimpleNamespace(
            content=content,
            reasoning_content=None,
            tool_calls=None,
        )
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])

    return _completion


class TestMemoryBeliefProvider:
    def test_payload_prepends_belief_block(self):
        mem = MemoryManager()
        mem.belief_provider = lambda: "## [COGNITION SNAPSHOT] Current Cognition\nBeliefs..."
        mem.record_execution(
            ToolResult(
                # preserve-class record: contains a decision-critical marker
                tool_name="curl_get", success=True, stdout="login successful flag{abc}",
                stderr="", exit_code=0, elapsed_ms=1.0,
            )
        )
        preserved, _, _ = mem.compression_payload()
        assert "Current Cognition" in preserved
        assert "flag{abc}" in preserved  # execution record still there

    def test_no_provider_keeps_legacy_payload(self):
        mem = MemoryManager()
        mem.record_execution(
            ToolResult(
                tool_name="curl_get", success=True, stdout="login successful flag{abc}",
                stderr="", exit_code=0, elapsed_ms=1.0,
            )
        )
        preserved, _, _ = mem.compression_payload()
        assert "Current Cognition" not in preserved
        assert "flag{abc}" in preserved

    def test_failing_provider_never_breaks_payload(self):
        mem = MemoryManager()
        mem.belief_provider = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        mem.record_execution(
            ToolResult(
                tool_name="curl_get", success=True, stdout="login successful flag{abc}",
                stderr="", exit_code=0, elapsed_ms=1.0,
            )
        )
        preserved, _, _ = mem.compression_payload()
        assert "flag{abc}" in preserved


class TestCompressMarkedMessages:
    @staticmethod
    def _history_with_marker(n_unmarked=8):
        """Build a history long enough to compress with a marked message."""
        history = [{"role": "system", "content": "sys"}]
        # The marked message sits in the OLD region (first messages) so the
        # compress partition logic actually has to route it to preservation.
        history.append(
            {"role": "user", "content": f"## {SNAPSHOT_MARKER} Current Cognition\nBelief: SQLI conf=70%"}
        )
        for i in range(n_unmarked):
            history.append({"role": "user", "content": f"regular message {i}"})
        return history

    def test_marked_content_survives_verbatim(self, monkeypatch):
        monkeypatch.setattr(
            "darwin.utils.llm.litellm.completion", _fake_completion()
        )
        llm = LLMSession()
        llm.conversation_history = self._history_with_marker()
        llm.compress(keep_recent=6, compression_threshold=0.0)

        assert llm._pending_compressed_context
        assert "Belief: SQLI conf=70%" in llm._pending_compressed_context
        assert "PRESERVED MEMORY" in llm._pending_compressed_context

    def test_summarizer_never_sees_marker(self, monkeypatch):
        seen = {}

        def _spy_completion(**kwargs):
            seen["messages"] = kwargs.get("messages", [])
            return _fake_completion()(**kwargs)

        monkeypatch.setattr("darwin.utils.llm.litellm.completion", _spy_completion)
        llm = LLMSession()
        llm.conversation_history = self._history_with_marker()
        llm.compress(keep_recent=6, compression_threshold=0.0)

        assert seen["messages"]
        joined = json.dumps(seen["messages"], ensure_ascii=False)
        assert SNAPSHOT_MARKER not in joined
        assert "Belief: SQLI conf=70%" not in joined

    def test_thought_log_records_compress_call(self, monkeypatch, tmp_path):
        # O4.2: thought-chain compatibility. The logger module lives on the
        # think-chain feature (not main); skip this test where it is absent
        # and run it once think-chain is merged.
        thought_logger = pytest.importorskip("darwin.utils.thought_logger")
        ThoughtLogger = thought_logger.ThoughtLogger
        THOUGHT_SUBDIR = thought_logger.THOUGHT_SUBDIR
        monkeypatch.setattr(
            "darwin.utils.llm.litellm.completion", _fake_completion()
        )
        logger = ThoughtLogger(run_id="compress_test", log_dir=str(tmp_path))
        llm = LLMSession(thought_logger=logger)
        llm.conversation_history = self._history_with_marker()
        llm.compress(keep_recent=6, compression_threshold=0.0)

        path = os.path.join(
            str(tmp_path), THOUGHT_SUBDIR, "compress_test_thoughts.jsonl"
        )
        assert os.path.exists(path)
        with open(path, encoding="utf-8") as fh:
            events = [json.loads(line) for line in fh if line.strip()]
        assert len(events) == 1
        assert events[0]["type"] == "llm_call"
        assert events[0]["stage"] == "compress"
        assert SNAPSHOT_MARKER not in str(events[0]["prompt"])

    def test_truncation_keeps_marked_messages(self, monkeypatch):
        monkeypatch.setattr(
            "darwin.utils.llm.litellm.completion", _fake_completion()
        )
        llm = LLMSession()
        llm._compressed_count = llm._max_compressions  # force truncation path
        llm.conversation_history = self._history_with_marker(n_unmarked=10)
        llm.compress(keep_recent=6, compression_threshold=0.0)

        joined = json.dumps(llm.conversation_history, ensure_ascii=False)
        assert "Belief: SQLI conf=70%" in joined
        assert "PRESERVED MEMORY" in joined

    def test_all_marked_skips_summarizer(self, monkeypatch):
        called = {"n": 0}

        def _spy_completion(**kwargs):
            called["n"] += 1
            return _fake_completion()(**kwargs)

        monkeypatch.setattr("darwin.utils.llm.litellm.completion", _spy_completion)
        llm = LLMSession()
        llm.conversation_history = [
            {"role": "user", "content": f"## {SNAPSHOT_MARKER} Current Cognition\nBelief: X"},
            {"role": "user", "content": f"## {SNAPSHOT_MARKER} Current Cognition\nBelief: Y"},
            {"role": "user", "content": f"## {SNAPSHOT_MARKER} Current Cognition\nBelief: Z"},
            {"role": "user", "content": "recent"},
        ]
        # keep_recent=2 and length > keep_recent+2 is required; use small keep
        llm.compress(keep_recent=1, compression_threshold=0.0)
        assert called["n"] == 0  # nothing compressible -> no LLM summarizer call
        assert "Belief: X" in llm._pending_compressed_context


class TestContextLimit384K:
    def test_default_max_context_tokens_is_384k(self):
        llm = LLMSession()
        assert llm.max_context_tokens == 384000

    def test_context_load_uses_instance_max(self, monkeypatch):
        monkeypatch.setattr(
            "darwin.utils.llm.litellm.token_counter",
            lambda **kwargs: 500,
        )
        llm = LLMSession(max_context_tokens=1000)
        assert llm.context_load == pytest.approx(0.5)
        big = LLMSession()
        assert big.context_load == pytest.approx(500 / 384000)

    def test_compress_uses_effective_max_for_load_check(self, monkeypatch):
        monkeypatch.setattr(
            "darwin.utils.llm.litellm.token_counter",
            lambda **kwargs: len(kwargs.get("messages", [])) * 100,
        )
        monkeypatch.setattr(
            "darwin.utils.llm.litellm.completion", _fake_completion()
        )
        llm = LLMSession(max_context_tokens=1000)
        llm.conversation_history = [
            {"role": "user", "content": "a"},
            {"role": "user", "content": "b"},
            {"role": "user", "content": "c"},
            {"role": "user", "content": "d"},
            {"role": "user", "content": "e"},
            {"role": "user", "content": "f"},
            {"role": "user", "content": "g"},
            {"role": "user", "content": "h"},
        ]
        # threshold 0.15 with 200/1000=0.2 load -> compresses
        assert llm.compress(keep_recent=2, compression_threshold=0.15) > 0


class TestStructuredDigestFirst:
    @staticmethod
    def _history(n_unmarked=6):
        history = [{"role": "system", "content": "sys"}]
        for i in range(n_unmarked):
            history.append({"role": "user", "content": f"raw tool output line {i}"})
        return history

    def test_summarizer_prefers_structured_digest(self, monkeypatch):
        seen = {}

        def _spy(**kwargs):
            seen["messages"] = kwargs.get("messages", [])
            return _fake_completion()(**kwargs)

        monkeypatch.setattr("darwin.utils.llm.litellm.completion", _spy)
        llm = LLMSession()
        llm.conversation_history = self._history()
        llm.compress(
            keep_recent=2,
            compression_threshold=0.0,
            structured_input="## Critical Facts\nCredential admin@t password=secret",
        )
        joined = json.dumps(seen["messages"], ensure_ascii=False)
        assert "STRUCTURED DIGEST" in joined
        assert "password=secret" in joined
        assert "raw tool output" not in joined

    def test_empty_structured_falls_back_to_raw_conversation(self, monkeypatch):
        seen = {}

        def _spy(**kwargs):
            seen["messages"] = kwargs.get("messages", [])
            return _fake_completion()(**kwargs)

        monkeypatch.setattr("darwin.utils.llm.litellm.completion", _spy)
        llm = LLMSession()
        llm.conversation_history = self._history()
        llm.compress(keep_recent=2, compression_threshold=0.0, structured_input="")
        joined = json.dumps(seen["messages"], ensure_ascii=False)
        assert "raw tool output" in joined
