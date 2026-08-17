"""Tests for LLMSession chain-of-thought capture (Design v2 P1/P1.1)."""

import json
import os
from types import SimpleNamespace

import pytest

from darwin.utils.llm import LLMSession
from darwin.utils.thought_logger import ThoughtLogger, THOUGHT_SUBDIR


def _fake_completion(content="ok", reasoning=None, tool_calls=None):
    def _completion(**kwargs):
        message = SimpleNamespace(
            content=content,
            reasoning_content=reasoning,
            tool_calls=tool_calls,
        )
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])

    return _completion


def _read_jsonl(logger):
    path = os.path.join(
        logger.log_dir, THOUGHT_SUBDIR, f"{logger.run_id}_thoughts.jsonl"
    )
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


@pytest.fixture
def logger(tmp_path):
    return ThoughtLogger(run_id="llm_test", log_dir=str(tmp_path / "thoughts"))


class TestLLMThoughtCapture:
    def test_reasoning_content_recorded_with_stage(
        self, monkeypatch, logger
    ):
        monkeypatch.setattr(
            "darwin.utils.llm.litellm.completion",
            _fake_completion(content="answer", reasoning="deep thinking"),
        )
        llm = LLMSession(model="deepseek/deepseek-v4-pro", thought_logger=logger)

        content, tool_calls = llm.generate("What now?", stage="analyze")

        assert content == "answer"
        assert tool_calls is None
        events = _read_jsonl(logger)
        assert len(events) == 1
        ev = events[0]
        assert ev["type"] == "llm_call"
        assert ev["stage"] == "analyze"
        assert ev["reasoning"] == "deep thinking"
        assert ev["prompt"] == "What now?"
        assert ev["content"] == "answer"
        # history keeps reasoning after the call (stripped later by _build_messages)
        assert llm.conversation_history[-1]["reasoning_content"] == "deep thinking"

    def test_reasoning_fallback_to_reasoning_field(self, monkeypatch, logger):
        def _completion(**kwargs):
            message = SimpleNamespace(
                content="ok",
                reasoning_content=None,
                reasoning="alternative field",
                tool_calls=None,
            )
            return SimpleNamespace(choices=[SimpleNamespace(message=message)])

        monkeypatch.setattr("darwin.utils.llm.litellm.completion", _completion)
        llm = LLMSession(thought_logger=logger)
        llm.generate("p", stage="plan")
        assert _read_jsonl(logger)[0]["reasoning"] == "alternative field"

    def test_stage_falls_back_to_logger_stage(self, monkeypatch, logger):
        monkeypatch.setattr(
            "darwin.utils.llm.litellm.completion", _fake_completion()
        )
        llm = LLMSession(thought_logger=logger)
        logger.set_stage("research")
        llm.generate("p")
        assert _read_jsonl(logger)[0]["stage"] == "research"

    def test_tool_calls_recorded_and_returned(self, monkeypatch, logger):
        tool_call = SimpleNamespace(
            id="call_1",
            function=SimpleNamespace(
                name="curl_get", arguments='{"url": "http://x/"}'
            ),
        )
        monkeypatch.setattr(
            "darwin.utils.llm.litellm.completion",
            _fake_completion(content="", tool_calls=[tool_call]),
        )
        llm = LLMSession(thought_logger=logger)
        content, parsed = llm.generate("p", stage="task_execution")
        assert parsed == [
            {"id": "call_1", "name": "curl_get", "arguments": {"url": "http://x/"}}
        ]
        ev = _read_jsonl(logger)[0]
        assert ev["tool_calls"][0]["name"] == "curl_get"

    def test_tool_result_recorded(self, monkeypatch, logger):
        monkeypatch.setattr(
            "darwin.utils.llm.litellm.completion", _fake_completion()
        )
        llm = LLMSession(thought_logger=logger)
        llm.add_tool_result("call_1", "HTTP 200")
        events = _read_jsonl(logger)
        assert events[0]["type"] == "tool_result"
        assert events[0]["tool_call_id"] == "call_1"
        assert events[0]["result"] == "HTTP 200"

    def test_reasoning_still_stripped_on_next_call(self, monkeypatch, logger):
        """Existing DeepSeek continuity behavior must be preserved."""
        seen_kwargs = {}

        def _completion(**kwargs):
            seen_kwargs.update(kwargs)
            return _fake_completion(
                content="answer", reasoning="thinking"
            )(**kwargs)

        monkeypatch.setattr("darwin.utils.llm.litellm.completion", _completion)
        llm = LLMSession(thought_logger=logger)
        llm.generate("first", stage="analyze")
        llm.generate("second", stage="plan")

        assert llm.conversation_history[-1]["content"] == "answer"
        assert all(
            "reasoning_content" not in msg
            for msg in seen_kwargs["messages"]
        )

    def test_without_logger_no_crash(self, monkeypatch):
        monkeypatch.setattr(
            "darwin.utils.llm.litellm.completion",
            _fake_completion(content="ok", reasoning="r"),
        )
        llm = LLMSession()
        content, tool_calls = llm.generate("p", stage="analyze")
        assert content == "ok"
        assert tool_calls is None
