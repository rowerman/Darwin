"""DARWIN Runner — Slim orchestrator entry point.

This module re-exports the Orchestrator class from darwin.app.orchestrator.
The orchestrator (darwin.app.orchestrator) contains the full solo-mode control
plane: bootstrap/recon, analysis, planning, and state management.

Usage:
    from darwin.app.runner import Orchestrator
    orch = Orchestrator(llm_session=llm)
    result = await orch.run("pentest target", "http://target")
"""

from darwin.app.orchestrator import Orchestrator, TaskResult  # noqa: F401
