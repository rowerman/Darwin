"""Tool contract layer (Phase 1: tool contract).

A :class:`ToolSpec` is the single source of truth for a tool's external
contract: name, version, description, domains, capability, parameter
schema, executor kind, dependencies, flags and output contract. Every
registered tool gets a ToolSpec (explicit, or auto-generated from the
registration call) so the rest of the framework — manifest generation,
domain filtering, coverage audit, LLM tool definitions — relies on one
stable contract instead of ad-hoc registration fields.

This module is intentionally dependency-free (no imports from the rest
of Darwin) so it can be imported by tests and tooling without pulling in
the LLM stack.
"""

from __future__ import annotations

import inspect
import shlex
import string
from dataclasses import dataclass, field
from typing import Any, Callable

CONTRACT_VERSION = "1.0.0"

# Executor kinds understood by the registry/executor.
EXECUTOR_PYTHON = "python"
EXECUTOR_SHELL = "shell"
EXECUTOR_SHELL_ARGV = "shell_argv"
EXECUTOR_MCP = "mcp"
EXECUTOR_KINDS = {
    EXECUTOR_PYTHON,
    EXECUTOR_SHELL,
    EXECUTOR_SHELL_ARGV,
    EXECUTOR_MCP,
}


@dataclass
class ToolSpec:
    """Declared external contract of one tool.

    ``parameters`` uses the OpenAI function-calling property format:
    ``{name: {"type": ..., "description": ..., "default": ...}}``.
    Required parameters are those without a ``default``.
    """

    name: str
    version: str = CONTRACT_VERSION
    description: str = ""
    domains: list[str] = field(default_factory=list)
    capability: str = ""
    parameters: dict[str, dict] = field(default_factory=dict)
    executor: str = EXECUTOR_PYTHON
    command_template: str = ""
    shell_args: list[str] = field(default_factory=list)
    split_params: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    flags: dict = field(default_factory=dict)
    output_contract: dict = field(default_factory=dict)
    aliases: dict[str, list[str]] = field(default_factory=dict)
    deprecated: bool = False
    auto: bool = False  # True when derived from a registration call

    @property
    def required(self) -> list[str]:
        """Parameter names without a declared default."""
        return [
            key
            for key, meta in self.parameters.items()
            if isinstance(meta, dict) and "default" not in meta
        ]

    def to_dict(self) -> dict[str, Any]:
        """Serializable dict (used by the manifest CLI)."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "domains": list(self.domains),
            "capability": self.capability,
            "parameters": {k: dict(v) for k, v in self.parameters.items()},
            "required": list(self.required),
            "executor": self.executor,
            "command_template": self.command_template,
            "shell_args": list(self.shell_args),
            "split_params": list(self.split_params),
            "dependencies": list(self.dependencies),
            "flags": dict(self.flags),
            "output_contract": dict(self.output_contract),
            "aliases": {k: list(v) for k, v in self.aliases.items()},
            "deprecated": self.deprecated,
            "auto": self.auto,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ToolSpec":
        """Rebuild a ToolSpec from :meth:`to_dict` output."""
        allowed = {
            "name", "version", "description", "domains", "capability",
            "parameters", "executor", "command_template", "shell_args",
            "split_params", "dependencies", "flags", "output_contract",
            "aliases", "deprecated", "auto",
        }
        return cls(**{k: v for k, v in data.items() if k in allowed})


def auto_spec(
    name: str,
    description: str,
    parameters: dict[str, dict],
    domain: str | None = None,
    executor: str = EXECUTOR_PYTHON,
    command_template: str = "",
    shell_args: list[str] | None = None,
    split_params: list[str] | None = None,
) -> ToolSpec:
    """Derive a ToolSpec from a legacy registration call."""
    return ToolSpec(
        name=name,
        description=description,
        domains=[domain] if domain else [],
        parameters=dict(parameters),
        executor=executor,
        command_template=command_template,
        shell_args=list(shell_args or []),
        split_params=list(split_params or []),
        auto=True,
    )


# ── Validation ─────────────────────────────────────────────────────


def _template_vars(template: str) -> set[str]:
    return {
        field_name
        for _, field_name, _, _ in string.Formatter().parse(template)
        if field_name is not None
    }


def _argv_vars(argv: list[str]) -> set[str]:
    vars_: set[str] = set()
    for element in argv:
        vars_.update(_template_vars(element))
    return vars_


def validate_spec(
    spec: ToolSpec,
    func: Callable | None = None,
) -> list[str]:
    """Return a list of contract violations (empty means valid)."""
    issues: list[str] = []
    if not spec.name:
        issues.append("tool name must not be empty")
    if not spec.description.strip():
        issues.append(f"tool '{spec.name}': description must not be empty")
    if spec.executor not in EXECUTOR_KINDS:
        issues.append(
            f"tool '{spec.name}': unknown executor '{spec.executor}' "
            f"(expected one of {sorted(EXECUTOR_KINDS)})"
        )

    for key, meta in spec.parameters.items():
        if not isinstance(meta, dict):
            issues.append(
                f"tool '{spec.name}': parameter '{key}' schema must be a dict"
            )
            continue
        if "type" not in meta:
            issues.append(
                f"tool '{spec.name}': parameter '{key}' schema missing 'type'"
            )
        if key in spec.aliases:
            issues.append(
                f"tool '{spec.name}': parameter '{key}' is both canonical "
                "and an alias"
            )

    # Alias sanity: alias targets must be declared parameters.
    for alias, canonicals in spec.aliases.items():
        if not canonicals:
            issues.append(
                f"tool '{spec.name}': alias '{alias}' has empty canonical list"
            )
        for canonical in canonicals:
            if canonical not in spec.parameters:
                issues.append(
                    f"tool '{spec.name}': alias '{alias}' points to undeclared "
                    f"parameter '{canonical}'"
                )

    if spec.executor == EXECUTOR_SHELL:
        declared = set(spec.parameters)
        used = _template_vars(spec.command_template)
        for var in used:
            if var not in declared:
                # False-positive guard: python -c scripts embed dict literals
                # such as {'error': ...} or NS={'saml': ...} which Formatter
                # misreads as placeholders.
                if any(marker in spec.command_template for marker in ("{'", '{"')):
                    continue
                issues.append(
                    f"tool '{spec.name}': template placeholder '{{{var}}}' "
                    "not declared in parameters"
                )
        for param in declared:
            meta = spec.parameters.get(param) or {}
            has_default = isinstance(meta, dict) and "default" in meta
            description = str((meta or {}).get("description", ""))
            if "alias for" in description.lower():
                continue  # alias-style params are intentionally unused
            if param not in used and not has_default:
                issues.append(
                    f"tool '{spec.name}': required parameter '{param}' is "
                    "never used by the command template"
                )

    if spec.executor == EXECUTOR_SHELL_ARGV:
        declared = set(spec.parameters)
        used = _argv_vars(spec.shell_args)
        for var in used:
            if var not in declared:
                issues.append(
                    f"tool '{spec.name}': shell_args placeholder '{{{var}}}' "
                    "not declared in parameters"
                )
        for param in declared:
            meta = spec.parameters.get(param) or {}
            has_default = isinstance(meta, dict) and "default" in meta
            if param not in used and not has_default:
                issues.append(
                    f"tool '{spec.name}': required parameter '{param}' is "
                    "never used by shell_args"
                )
        for param in spec.split_params:
            if param not in declared:
                issues.append(
                    f"tool '{spec.name}': split_params '{param}' not declared "
                    "in parameters"
                )

    if func is not None:
        issues.extend(_validate_python_signature(spec, func))
    return issues


def _validate_python_signature(spec: ToolSpec, func: Callable) -> list[str]:
    """Check the callable signature against the declared parameter schema."""
    issues: list[str] = []
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError):
        return issues  # builtins/unsupported: skip signature check

    declared = set(spec.parameters)
    has_var_kwargs = any(
        p.kind == inspect.Parameter.VAR_KEYWORD
        for p in signature.parameters.values()
    )
    for name, param in signature.parameters.items():
        if param.kind in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            continue
        if name not in declared and not has_var_kwargs:
            issues.append(
                f"tool '{spec.name}': function parameter '{name}' not "
                "declared in schema (and no **kwargs)"
            )
    for name in spec.required:
        if name not in signature.parameters:
            issues.append(
                f"tool '{spec.name}': required schema parameter '{name}' "
                "missing from function signature"
            )
    return issues


def check_all_specs(
    specs: dict[str, ToolSpec],
    funcs: dict[str, Callable] | None = None,
    strict: bool = False,
) -> list[str]:
    """Validate every spec; return all issues (empty means all valid)."""
    funcs = funcs or {}
    all_issues: list[str] = []
    for name, spec in specs.items():
        issues = validate_spec(spec, funcs.get(name))
        if issues and not strict:
            # Non-strict: report as warnings, keep framework running.
            all_issues.extend(f"[warn] {issue}" for issue in issues)
        elif issues:
            all_issues.extend(f"[error] {issue}" for issue in issues)
    return all_issues


def shlex_split_value(value: Any) -> list[str]:
    """Split a free-form command string like the old shell path did."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    text = str(value)
    return shlex.split(text) if text.strip() else []
