"""Tests for PhaseLogger — structured file-based phase logging."""

import json
import os
import pytest
from darwin.utils.phase_logger import PhaseLogger


@pytest.fixture
def temp_log_dir(tmp_path):
    """Provide a temporary log directory."""
    return str(tmp_path / "test_logs")


@pytest.fixture
def logger(temp_log_dir):
    """Create a PhaseLogger instance for testing."""
    return PhaseLogger(run_id="20260625_test", log_dir=temp_log_dir)


class TestPhaseLoggerBasic:
    """Basic PhaseLogger operations."""

    def test_creates_log_file(self, logger, temp_log_dir):
        """log_phase should create a file in the correct subdirectory."""
        filepath = logger.log_phase("bootstrap", "test content", metadata={"services": 5})
        assert filepath is not None
        assert os.path.exists(filepath)
        assert "scan" in filepath
        assert "20260625_test_bootstrap.log" in filepath

    def test_file_contains_json_header(self, logger, temp_log_dir):
        """The log file should start with a JSON header line."""
        logger.log_phase("analyze", "vuln data here", metadata={"vuln_count": 3})
        filepath = os.path.join(temp_log_dir, "research", "20260625_test_analyze.log")
        with open(filepath, encoding="utf-8") as f:
            first_line = f.readline().strip()
        header = json.loads(first_line)
        assert header["phase"] == "analyze"
        assert header["run_id"] == "20260625_test"
        assert "timestamp" in header

    def test_file_has_content_separator(self, logger, temp_log_dir):
        """The file should contain the ---CONTENT--- separator."""
        logger.log_phase("plan", "plan content")
        filepath = os.path.join(temp_log_dir, "plan", "20260625_test_plan.log")
        content = open(filepath, encoding="utf-8").read()
        assert "---CONTENT---" in content
        assert "plan content" in content

    def test_content_after_separator(self, logger, temp_log_dir):
        """Content after the separator should be readable."""
        logger.log_phase("exploit", "exploit output line 1\nexploit output line 2")
        retrieved = logger.get_phase_content("exploit")
        assert retrieved is not None
        assert "exploit output line 1" in retrieved
        assert "exploit output line 2" in retrieved

    def test_empty_content(self, logger):
        """Empty content should still create a valid log file."""
        filepath = logger.log_phase("deep_recon", "")
        assert filepath is not None
        assert os.path.exists(filepath)

    def test_disabled_logger(self, temp_log_dir):
        """When enabled=False, no files should be created."""
        disabled = PhaseLogger("test", log_dir=temp_log_dir, enabled=False)
        result = disabled.log_phase("bootstrap", "content")
        assert result is None
        # Directory should not be created
        assert not os.path.exists(os.path.join(temp_log_dir, "scan"))


class TestPhaseLoggerDirMapping:
    """Phase-to-subdirectory mapping."""

    @pytest.mark.parametrize("phase,expected_dir", [
        ("bootstrap", "scan"),
        ("k8s_discovery", "scan"),
        ("deep_recon", "recon"),
        ("cloud_discovery", "recon"),
        ("defense_detection", "recon"),
        ("service_research", "research"),
        ("analyze", "research"),
        ("research_phase", "research"),
        ("plan", "plan"),
        ("plan_exhausted", "plan"),
        ("exploit", "exploit"),
        ("systematic_exploit", "exploit"),
        ("fix_and_retry", "exploit"),
        ("replan", "replan"),
        ("plan_review", "replan"),
        ("summary", "summary"),
    ])
    def test_phase_dir_mapping(self, temp_log_dir, phase, expected_dir):
        """Each phase should go to the correct subdirectory."""
        logger = PhaseLogger("test_run", log_dir=temp_log_dir)
        filepath = logger.log_phase(phase, "content")
        assert expected_dir in filepath

    def test_unknown_phase_goes_to_other(self, temp_log_dir):
        """Unknown phase names should go to 'other' directory."""
        logger = PhaseLogger("test_run", log_dir=temp_log_dir)
        filepath = logger.log_phase("unknown_phase_name", "content")
        assert "other" in filepath


class TestPhaseLoggerTiming:
    """Phase timing via start_phase / end_phase."""

    def test_end_phase_records_elapsed(self, logger, temp_log_dir):
        """end_phase should record elapsed time in the metadata."""
        logger.start_phase("exploit")
        filepath = logger.end_phase("exploit", "content")
        assert filepath is not None

        # Read back the header
        with open(filepath, encoding="utf-8") as f:
            first_line = f.readline().strip()
        header = json.loads(first_line)
        assert "elapsed_s" in header
        elapsed = float(header["elapsed_s"])
        assert elapsed >= 0

    def test_log_phase_without_start(self, logger):
        """log_phase without start_phase should not crash."""
        filepath = logger.log_phase("plan", "content")
        assert filepath is not None


class TestPhaseLoggerSummary:
    """Summary file generation."""

    def test_write_summary_creates_file(self, logger, temp_log_dir):
        """write_summary should create a summary file."""
        logger.log_phase("bootstrap", "scan content")
        logger.log_phase("analyze", "analysis content")

        filepath = logger.write_summary(None, dkg_summary="dkg data")
        assert filepath is not None
        assert os.path.exists(filepath)
        assert "summary" in filepath

        content = open(filepath, encoding="utf-8").read()
        assert "DARWIN Run Summary" in content
        assert "dkg data" in content

    def test_write_summary_lists_phase_files(self, logger, temp_log_dir):
        """Summary should list all phase log files that were written."""
        logger.log_phase("bootstrap", "scan content")
        logger.log_phase("deep_recon", "recon content")

        filepath = logger.write_summary(None)
        content = open(filepath, encoding="utf-8").read()
        assert "bootstrap" in content or "scan" in content
        assert "deep_recon" in content

    def test_disabled_summary(self, temp_log_dir):
        """Disabled logger should not create summary."""
        logger = PhaseLogger("test", log_dir=temp_log_dir, enabled=False)
        result = logger.write_summary(None)
        assert result is None

    def test_summary_with_task_result(self, logger, temp_log_dir):
        """Summary should include task result fields."""
        from dataclasses import dataclass

        @dataclass
        class FakeResult:
            success: bool = True
            flag: str = "flag{test_123}"
            steps: int = 5
            tokens_used: int = 42000
            time_elapsed: float = 67.3
            error: str = ""
            defense_detected: bool = True
            waf_bypassed: bool = True
            waf_type: str = "modsecurity"

        result = FakeResult()
        filepath = logger.write_summary(result)
        content = open(filepath, encoding="utf-8").read()
        assert "flag{test_123}" in content
        assert "steps: 5" in content


class TestPhaseLoggerSharedMetadata:
    """Shared metadata across phases."""

    def test_set_shared_metadata(self, logger, temp_log_dir):
        """Shared metadata should be available for log_phase calls."""
        logger.set_shared_metadata(target="example.com", model="test-model")
        logger.log_phase("bootstrap", "content")
        # The shared metadata is available via _metadata but isn't automatically
        # merged into file headers unless passed explicitly
        assert logger._metadata["target"] == "example.com"
        assert logger._metadata["model"] == "test-model"


class TestPhaseLoggerGetPhaseContent:
    """Reading back phase content."""

    def test_get_existing_phase(self, logger):
        """get_phase_content should return the content of a written phase."""
        logger.log_phase("plan", "plan content here")
        content = logger.get_phase_content("plan")
        assert content == "plan content here\n"

    def test_get_missing_phase(self, logger):
        """get_phase_content should return None for unwritten phases."""
        content = logger.get_phase_content("nonexistent")
        assert content is None

    def test_get_content_empty_phase(self, logger):
        """get_phase_content should work for empty content phases."""
        logger.log_phase("replan", "")
        content = logger.get_phase_content("replan")
        assert content == ""


class TestPhaseLoggerEdgeCases:
    """Edge case handling."""

    def test_metadata_with_unserializable_values(self, logger, temp_log_dir):
        """Non-JSON-serializable metadata should be converted to strings."""
        logger.log_phase("bootstrap", "content",
                         metadata={"complex_obj": object()})
        filepath = os.path.join(temp_log_dir, "scan",
                                "20260625_test_bootstrap.log")
        with open(filepath, encoding="utf-8") as f:
            first_line = f.readline().strip()
        header = json.loads(first_line)
        assert "complex_obj" in header
        assert isinstance(header["complex_obj"], str)

    def test_content_without_trailing_newline(self, logger, temp_log_dir):
        """Content without trailing newline should get one added."""
        logger.log_phase("bootstrap", "no newline")
        filepath = os.path.join(temp_log_dir, "scan",
                                "20260625_test_bootstrap.log")
        content = open(filepath, encoding="utf-8").read()
        assert content.endswith("\n")

    def test_custom_run_id(self, temp_log_dir):
        """Custom run_id should be reflected in filenames."""
        logger = PhaseLogger("custom_123", log_dir=temp_log_dir)
        filepath = logger.log_phase("bootstrap", "content")
        assert "custom_123" in filepath
