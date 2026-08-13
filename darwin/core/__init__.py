"""DARWIN v2 core contracts — component interfaces and shared types.

P2 deliverable: interface-first contracts for the v2 control plane
(Planner / Scheduler / Executor / Evaluator / Memory). The orchestrator
still owns the runtime implementation; these types are introduced now and
wired incrementally in later milestones (P3 Task model, P5 Executor,
P6 Evaluator, P10 Memory, P15 Runtime).
"""

from darwin.core.contracts import (
    Budget,
    Executor,
    Objective,
    Planner,
    ReplanRecommendation,
    Scheduler,
    TaskOutcome,
    TaskStatus,
    WorldState,
)
from darwin.core.capabilities import (
    Capability,
    CapabilityRegistry,
    ContextResolver,
    PreconditionValidator,
    default_registry,
)
from darwin.core.events import RuntimeEvent
from darwin.core.evaluator import (
    Classification,
    Evaluation,
    Evaluator,
    FailureAnalyzer,
    FailureType,
)
from darwin.core.executor import ExecutionResult, ToolExecutor
from darwin.core.parameters import (
    ParamIssue,
    ParameterCorrector,
    ParameterValidator,
    ToolSchema,
    ToolSchemaProvider,
)
from darwin.core.replan import LocalRepair, Replanner
from darwin.core.runtime import Runtime
from darwin.core.task import Task
from darwin.core.task_graph import DependencyType, TaskGraph

__all__ = [
    "Budget",
    "Capability",
    "CapabilityRegistry",
    "Classification",
    "ContextResolver",
    "DependencyType",
    "Evaluation",
    "Evaluator",
    "ExecutionResult",
    "Executor",
    "FailureAnalyzer",
    "FailureType",
    "LocalRepair",
    "Objective",
    "ParamIssue",
    "ParameterCorrector",
    "ParameterValidator",
    "Planner",
    "PreconditionValidator",
    "ReplanRecommendation",
    "Replanner",
    "Runtime",
    "RuntimeEvent",
    "Scheduler",
    "Task",
    "TaskGraph",
    "TaskOutcome",
    "TaskStatus",
    "ToolSchema",
    "ToolSchemaProvider",
    "ToolExecutor",
    "WorldState",
    "default_registry",
]
