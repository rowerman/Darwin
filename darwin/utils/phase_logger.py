"""PhaseLogger — structured file-based logging for DARWIN penetration test phases.

Creates log/<phase_subdir>/<run_id>_<phase>.log files at phase boundaries.
Does NOT replace or intercept stdout — it is an ADDITIONAL sink that writes
phase-scoped content (already printed to console) to timestamped files.

Directory structure:
    log/
      scan/         # nmap, K8s discovery, bootstrap
      recon/        # dirb, nikto, whatweb, form extraction, defense detection
      research/     # CVE search, RAG results, vulnerability analysis
      plan/         # exploitation plans, thin-plan warnings
      exploit/      # systematic exploit, plan-driven exploit, fix-and-retry
      replan/       # plan review, plan update, replan
      summary/      # final run summary
"""

from __future__ import annotations

import json
import logging
import os
import time
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)


class PhaseLogger:
    """Structured phase logging: writes phase output to log/<phase>/<run_id>_<phase>.log.

    Usage in Orchestrator:
        self.phase_logger = PhaseLogger(run_id="20260625_154214", log_dir="log")
        self.phase_logger.log_phase("bootstrap", services_summary, metadata={...})
        ...
        self.phase_logger.write_summary(task_result, dkg_summary)
    """

    # Map logical phase names to subdirectory names
    PHASE_DIR_MAP: Dict[str, str] = {
        # Scan phase
        "bootstrap":           "scan",
        "k8s_discovery":       "scan",
        # Recon phase
        "deep_recon":          "recon",
        "cloud_discovery":     "recon",
        "defense_detection":   "recon",
        # Research phase
        "service_research":    "research",
        "analyze":             "research",
        "research_phase":      "research",
        # Plan phase
        "plan":                "plan",
        "plan_exhausted":      "plan",
        # Exploit phase
        "exploit":             "exploit",
        "systematic_exploit":  "exploit",
        "fix_and_retry":       "exploit",
        # Replan phase
        "replan":              "replan",
        "plan_review":         "replan",
        # Generic
        "summary":             "summary",
    }

    def __init__(
        self,
        run_id: str,
        log_dir: str = "log",
        log_level: str = "INFO",
        enabled: bool = True,
    ):
        self.run_id = run_id
        self.log_dir = log_dir
        self.log_level = log_level.upper()
        self.enabled = enabled
        self._phase_times: Dict[str, float] = {}
        self._created_dirs: set[str] = set()
        self._metadata: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Directory helpers
    # ------------------------------------------------------------------

    def ensure_dir(self, subdir: str) -> str:
        """Create log/<subdir>/ if it doesn't exist. Returns the absolute path."""
        path = os.path.join(self.log_dir, subdir)
        if path not in self._created_dirs:
            os.makedirs(path, exist_ok=True)
            self._created_dirs.add(path)
        return path

    def phase_subdir(self, phase_name: str) -> str:
        """Resolve a logical phase name to its subdirectory name."""
        return self.PHASE_DIR_MAP.get(phase_name, "other")

    # ------------------------------------------------------------------
    # Core write method
    # ------------------------------------------------------------------

    def log_phase(
        self,
        phase_name: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """Write phase-scoped content to log/<subdir>/<run_id>_<phase>.log.

        Args:
            phase_name: Logical phase name (bootstrap, deep_recon, analyze, etc.)
            content: Phase output text (typically what was also printed to console)
            metadata: Optional dict of structured data to include as JSON header

        Returns:
            The file path written, or None if logging is disabled.
        """
        if not self.enabled:
            return None

        subdir = self.phase_subdir(phase_name)
        dir_path = self.ensure_dir(subdir)

        elapsed = ""
        start = self._phase_times.pop(phase_name, None)
        if start is not None:
            elapsed = f"{time.time() - start:.3f}"

        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())

        filename = f"{self.run_id}_{phase_name}.log"
        filepath = os.path.join(dir_path, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            # JSON header — single line, machine-parseable
            header: Dict[str, Any] = {
                "phase": phase_name,
                "timestamp": timestamp,
                "run_id": self.run_id,
                "elapsed_s": elapsed if elapsed else "N/A",
            }
            if metadata:
                for k, v in metadata.items():
                    try:
                        json.dumps(v)  # test serializability
                        header[k] = v
                    except (TypeError, ValueError):
                        header[k] = str(v)
            f.write(json.dumps(header, default=str) + "\n")
            f.write("---CONTENT---\n")
            f.write(content)
            if content and not content.endswith("\n"):
                f.write("\n")

        if self.log_level == "DEBUG":
            log.debug("Phase log written: %s (%d bytes)", filepath, len(content))
        return filepath

    # ------------------------------------------------------------------
    # Phase timing (context manager + explicit start/end)
    # ------------------------------------------------------------------

    @contextmanager
    def phase_context(self, phase_name: str):
        """Context manager: starts timing on entry.

        The orchestrator must call log_phase() or end_phase() within the
        context to actually write the file. The context manager itself only
        manages timing.
        """
        self._phase_times[phase_name] = time.time()
        try:
            yield
        finally:
            pass

    def start_phase(self, phase_name: str) -> None:
        """Start phase timing (alternative to context manager)."""
        self._phase_times[phase_name] = time.time()

    def end_phase(
        self,
        phase_name: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """End phase timing and write the output file."""
        if metadata is None:
            metadata = {}
        if phase_name in self._phase_times:
            elapsed = time.time() - self._phase_times.pop(phase_name)
            metadata["elapsed_s"] = round(elapsed, 3)
        return self.log_phase(phase_name, content, metadata)

    # ------------------------------------------------------------------
    # Shared metadata
    # ------------------------------------------------------------------

    def set_shared_metadata(self, **kwargs: Any) -> None:
        """Set metadata shared across all subsequent phase logs."""
        self._metadata.update(kwargs)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def write_summary(
        self,
        task_result: Any,
        dkg_summary: str = "",
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """Write final run summary to log/summary/<run_id>_summary.log."""
        if not self.enabled:
            return None

        subdir = "summary"
        dir_path = self.ensure_dir(subdir)
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
        filename = f"{self.run_id}_summary.log"
        filepath = os.path.join(dir_path, filename)

        lines = [
            f"DARWIN Run Summary — {self.run_id}",
            f"Timestamp: {timestamp}",
            f"{'=' * 60}",
        ]

        if extra_metadata:
            for k, v in extra_metadata.items():
                lines.append(f"{k}: {v}")

        if dkg_summary:
            lines.append(f"\nDKG Summary:\n{dkg_summary}")

        if task_result is not None:
            lines.append("\nResult:")
            for attr in ("success", "flag", "steps", "tokens_used",
                         "time_elapsed", "error", "defense_detected",
                         "waf_bypassed", "waf_type"):
                val = getattr(task_result, attr, None)
                if val is not None:
                    if attr == "time_elapsed":
                        val = f"{val:.1f}s"
                    lines.append(f"  {attr}: {val}")

        # List all phase log files written
        lines.append("\nPhase Logs:")
        for phase_name in sorted(self.PHASE_DIR_MAP):
            phase_dir = self.phase_subdir(phase_name)
            phase_file = f"{self.run_id}_{phase_name}.log"
            full_path = os.path.join(self.log_dir, phase_dir, phase_file)
            if os.path.exists(full_path):
                fsize = os.path.getsize(full_path)
                lines.append(f"  {full_path} ({fsize} bytes)")

        content = "\n".join(lines) + "\n"
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        log.info("Run summary written to %s", filepath)
        return filepath

    # ------------------------------------------------------------------
    # Read-back utility
    # ------------------------------------------------------------------

    def get_phase_content(
        self,
        phase_name: str,
        run_id: Optional[str] = None,
    ) -> Optional[str]:
        """Read back a previously-written phase log file.

        Returns the content portion (after ---CONTENT---) or None.
        """
        rid = run_id or self.run_id
        subdir = self.phase_subdir(phase_name)
        filename = f"{rid}_{phase_name}.log"
        filepath = os.path.join(self.log_dir, subdir, filename)
        try:
            with open(filepath, encoding="utf-8") as f:
                lines = f.readlines()
            content_start = 0
            for i, line in enumerate(lines):
                if line.strip() == "---CONTENT---":
                    content_start = i + 1
                    break
            return "".join(lines[content_start:])
        except (FileNotFoundError, IOError):
            return None
