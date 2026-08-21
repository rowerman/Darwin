"""DARWIN orchestration package — decoupled orchestrator phase coordinators.

The Orchestrator (``darwin.orchestrator``) composes these coordinators through a
shared context: all state lives on the Orchestrator instance; coordinators
forward unknown attributes/methods to it and call tools via the injected
``ToolCallPort``.
"""
from darwin.orchestration.context import CoordinatorContext
from darwin.orchestration.execution import (
    ExecutionCoordinator,
    TaskExecution,
    _RuntimeFlagFound,
    _RuntimePlannerAdapter,
    _RuntimeExecutorAdapter,
    _RuntimeEvaluatorAdapter,
)
from darwin.orchestration.lifecycle import LifecycleCoordinator
from darwin.orchestration.planning import PlanCoordinator
from darwin.orchestration.ports import GatewayToolCallPort, ToolCallPort
from darwin.orchestration.recon import ReconCoordinator
from darwin.orchestration.research import ResearchCoordinator

__all__ = [
    "CoordinatorContext",
    "ExecutionCoordinator",
    "GatewayToolCallPort",
    "LifecycleCoordinator",
    "PlanCoordinator",
    "ReconCoordinator",
    "ResearchCoordinator",
    "TaskExecution",
    "ToolCallPort",
    "_RuntimeFlagFound",
    "_RuntimePlannerAdapter",
    "_RuntimeExecutorAdapter",
    "_RuntimeEvaluatorAdapter",
]
