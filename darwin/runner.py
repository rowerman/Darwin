"""DARWIN Runner — Slim orchestrator entry point.

This module re-exports the Orchestrator class from darwin.orchestrator.
The orchestrator has been modularized: bootstrap, analysis, planning, and
state management logic live in separate modules (darwin.bootstrap,
darwin.analyzer, darwin.planner, darwin.state).

Usage:
    from darwin.runner import Orchestrator
    orch = Orchestrator(llm_session=llm)
    result = await orch.run("pentest target", "http://target")
"""

from darwin.orchestrator import Orchestrator, TaskResult  # noqa: F401
