"""Tests for ThoughtLogger — LLM chain-of-thought persistence (Design v2 P0)."""

import json
import os

import pytest

from darwin.utils.thought_logger import ThoughtLogger, THOUGHT_SUBDIR


@pytest.fixture
def temp_log_dir(tmp_path):
    return str(tmp_path / "test_thoughts")


@pytest.fixture
def logger(temp_log_dir):
    return ThoughtLogger(run_id="20260625_test", log_dir=temp_log_dir)


def _read_jsonl(logger):
    path = os.path.join(
        logger.log_dir, THOUGHT_SUBDIR, f"{logger.run_id}_thoughts.jsonl"
    )
    assert os.path.exists(path), f"missing {path}"
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


class TestThoughtLoggerCall:
    def test_record_call_writes_parseable_jsonl(self, logger):
        logger.record_call(
            stage="analyze",
            model="deepseek/deepseek-v4-pro",
            prompt="What services are here?",
            system_prompt="You are a pentester.",
            reasoning="Port 8080 looks like Tomcat.",
            content='[{"vuln_type": "RCE"}]',
            tool_calls=None,
        )
        events = _read_jsonl(logger)
        assert len(events) == 1
        ev = events[0]
        assert ev["type"] == "llm_call"
        assert ev["stage"] == "analyze"
        assert ev["model"] == "deepseek/deepseek-v4-pro"
        assert ev["prompt"] == "What services are here?"
        assert ev["reasoning"] == "Port 8080 looks like Tomcat."
        assert ev["content"] == '[{"vuln_type": "RCE"}]'
        assert ev["tool_calls"] is None
        assert ev["seq"] == 1

    def test_record_call_writes_readable_log(self, logger):
        logger.record_call(
            stage="plan", model="m", prompt="plan it",
            system_prompt=None, reasoning="think", content="ok", tool_calls=None,
        )
        log_path = os.path.join(
            logger.log_dir, THOUGHT_SUBDIR, f"{logger.run_id}_thoughts.log"
        )
        content = open(log_path, encoding="utf-8").read()
        assert "chain of thought" in content
        assert "plan it" in content
        assert "think" in content

    def test_stage_fallback_uses_current_stage(self, logger):
        logger.record_call(
            stage=None, model="m", prompt="p",
            system_prompt=None, reasoning=None, content="c", tool_calls=None,
        )
        assert _read_jsonl(logger)[0]["stage"] == "main_loop"

    def test_stage_context_manager(self, logger):
        assert logger.current_stage == "main_loop"
        with logger.stage("research"):
            assert logger.current_stage == "research"
        assert logger.current_stage == "main_loop"
        logger.set_stage("exploit")
        logger.record_call(
            stage=None, model="m", prompt="p",
            system_prompt=None, reasoning=None, content="c", tool_calls=None,
        )
        assert _read_jsonl(logger)[0]["stage"] == "exploit"


class TestThoughtLoggerToolResult:
    def test_record_tool_result(self, logger):
        logger.record_call(
            stage="task_execution", model="m", prompt="p",
            system_prompt=None, reasoning="r", content="c",
            tool_calls=[{"id": "call_1", "name": "curl_get", "arguments": {}}],
        )
        logger.record_tool_result("call_1", "HTTP 200: flag{test}")
        events = _read_jsonl(logger)
        assert len(events) == 2
        tr = events[1]
        assert tr["type"] == "tool_result"
        assert tr["tool_call_id"] == "call_1"
        assert tr["result"] == "HTTP 200: flag{test}"
        assert tr["stage"] == "task_execution"


class TestThoughtLoggerEdgeCases:
    def test_disabled_no_files(self, temp_log_dir):
        disabled = ThoughtLogger("test", log_dir=temp_log_dir, enabled=False)
        disabled.record_call(
            stage="analyze", model="m", prompt="p",
            system_prompt=None, reasoning="r", content="c", tool_calls=None,
        )
        disabled.record_tool_result("call_1", "out")
        assert not os.path.exists(os.path.join(temp_log_dir, THOUGHT_SUBDIR))

    def test_unwritable_dir_swallows_error(self, tmp_path):
        # log_dir/thought exists as a FILE → makedirs raises OSError.
        block = tmp_path / "log"
        block.mkdir()
        (block / THOUGHT_SUBDIR).write_text("not a dir", encoding="utf-8")
        logger = ThoughtLogger("test", log_dir=str(block))
        # Should not raise.
        logger.record_call(
            stage="analyze", model="m", prompt="p",
            system_prompt=None, reasoning=None, content="c", tool_calls=None,
        )
        logger.record_tool_result("call_1", "out")

    def test_non_serializable_tool_calls_do_not_break(self, logger):
        logger.record_call(
            stage="plan", model="m", prompt="p",
            system_prompt=None, reasoning=None, content="c",
            tool_calls=[{"name": "x", "arguments": object()}],
        )
        # default=str converts the object; file must still be parseable JSON.
        events = _read_jsonl(logger)
        assert events[0]["tool_calls"][0]["name"] == "x"
