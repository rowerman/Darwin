"""Tests for the P3 ContextManager (darwin.core.context)."""

from darwin.core.context import ContextManager
from darwin.core.executor import ExecutionResult
from darwin.core.memory import MemoryManager
from darwin.dkg import DKG


class RecordingLLM:
    """Minimal LLMSession stand-in recording compress() calls."""

    def __init__(self, context_load=0.0, token_count=100, saved=0):
        self.context_load = context_load
        self.token_count = token_count
        self.max_context_tokens = 384000
        self._compressed_count = 0
        self._saved = saved
        self.compress_calls = []

    def compress(self, **kwargs):
        self.compress_calls.append(kwargs)
        return self._saved


def _result(**overrides):
    base = dict(
        task_id="t1",
        tool="curl_get",
        planned_tool="curl_get",
        adherence=True,
        success=True,
        stdout="dir listing",
        stderr="",
        exit_code=0,
        elapsed_ms=5.0,
    )
    base.update(overrides)
    return ExecutionResult(**base)


def test_skips_when_below_threshold():
    llm = RecordingLLM(context_load=0.1)
    ctx = ContextManager(llm=llm, memory=MemoryManager(), compression_threshold=0.4)
    assert ctx.maybe_compress() is False
    assert llm.compress_calls == []


def test_syncs_session_max_context_tokens():
    """P1 fix: ContextManager is the single source of truth for the window."""
    llm = RecordingLLM()
    ContextManager(llm=llm, memory=MemoryManager(), max_context_tokens=128000)
    assert llm.max_context_tokens == 128000


def test_compresses_with_preserved_and_structured():
    llm = RecordingLLM(context_load=0.9, saved=120)
    mem = MemoryManager()
    mem.critical_facts_provider = lambda: "Credential admin@t password=secret123"
    mem.record_execution(_result())
    ctx = ContextManager(llm=llm, memory=mem, compression_threshold=0.4)

    assert ctx.maybe_compress() is True
    assert len(llm.compress_calls) == 1
    kwargs = llm.compress_calls[0]
    assert kwargs["max_context_tokens"] == 384000
    assert "secret123" in kwargs["structured_input"]
    assert "[curl_get]" in kwargs["structured_input"]
    assert kwargs["truncation_context"]
    assert kwargs["preserved_context"] == ""  # no belief provider / preserved records


def test_tokens_exceeded_compresses_before_giving_up():
    llm = RecordingLLM(context_load=0.9, token_count=500, saved=0)
    ctx = ContextManager(llm=llm, memory=MemoryManager(), compression_threshold=0.4)
    assert ctx.tokens_exceeded(100) is True
    assert len(llm.compress_calls) == 1


def test_tokens_exceeded_false_within_budget():
    llm = RecordingLLM(token_count=50)
    ctx = ContextManager(llm=llm, memory=MemoryManager())
    assert ctx.tokens_exceeded(100) is False
    assert llm.compress_calls == []


def test_truncation_uses_belief_provider_when_wired():
    mem = MemoryManager()
    mem.belief_provider = lambda: "## [COGNITION SNAPSHOT] Current Cognition\nBeliefs..."
    ctx = ContextManager(llm=RecordingLLM(), memory=mem)
    assert "Beliefs..." in ctx.truncation_context()


def test_truncation_falls_back_to_dkg_summary():
    dkg = DKG()
    dkg.add_node("Flag", "f1", {"value": "flag{x}"})
    mem = MemoryManager()
    mem.belief_provider = lambda: ""
    ctx = ContextManager(llm=RecordingLLM(), memory=mem, dkg=dkg)
    text = ctx.truncation_context()
    assert "DKG STATE AT TRUNCATION" in text
    assert "flag{x}" in text


def test_event_logger_receives_compression_event():
    events = []
    llm = RecordingLLM(context_load=0.9, saved=300)
    ctx = ContextManager(
        llm=llm,
        memory=MemoryManager(),
        event_logger=lambda *args, **kwargs: events.append((args, kwargs)),
    )
    assert ctx.maybe_compress() is True
    assert len(events) == 1
    assert events[0][0][1] == "context_compressed"
    assert events[0][1]["tokens_saved"] == 300
