"""Stage A: versioned pydantic schemas for inter-phase LLM outputs."""

import pytest

from darwin.core.schemas import (
    AnalyzeOutputV1,
    PlanTaskV1,
    ResearchFindingV1,
    ServiceResearchFindingV1,
    extract_json_value,
    parse_analyze_output,
    parse_plan_tasks,
    parse_research_findings,
    parse_service_research_findings,
)


# ── Extraction ──────────────────────────────────────────────────────


def test_extract_direct_json():
    assert extract_json_value('{"a": 1}') == {"a": 1}
    assert extract_json_value("[1, 2]") == [1, 2]


def test_extract_fenced_code_block():
    text = 'Here is the output:\n```json\n{"a": 1}\n```\nthanks'
    assert extract_json_value(text) == {"a": 1}


def test_extract_array_with_trailing_text():
    text = 'Plan:\n[{"id": "t1"}]\n-- end'
    assert extract_json_value(text) == [{"id": "t1"}]


def test_extract_none_for_garbage():
    assert extract_json_value("no json here") is None
    assert extract_json_value("") is None
    assert extract_json_value(None) is None


# ── Analyze output ──────────────────────────────────────────────────


def test_parse_analyze_output_valid_dict():
    text = """
    ```json
    {
      "application_understanding": "A small blog app",
      "vulnerabilities": [
        {"vuln_type": "SQLi", "endpoint": "http://x?id=1", "param": "id",
         "confidence": 0.8, "evidence": "error based", "suggested_tool": "sqlmap_test",
         "tool_args": {"url": "http://x", "param": "id"}}
      ],
      "attack_paths": [
        {"path_id": "path-1", "description": "chain", "steps": [{"step": 1}]}
      ]
    }
    ```
    """
    model, err = parse_analyze_output(text)
    assert err == ""
    assert model is not None
    assert model.application_understanding == "A small blog app"
    assert len(model.vulnerabilities) == 1
    assert model.vulnerabilities[0].vuln_type == "SQLi"
    assert model.vulnerabilities[0].confidence == 0.8
    assert model.attack_paths[0].id == "path-1"  # path_id canonicalized


def test_parse_analyze_output_legacy_flat_array():
    text = '[{"vuln_type": "XSS", "endpoint": "http://x"}]'
    model, err = parse_analyze_output(text)
    assert err == ""
    assert model is not None
    assert model.application_understanding == ""
    assert model.vulnerabilities[0].vuln_type == "XSS"


def test_parse_analyze_output_drops_extra_fields():
    text = (
        '{"application_understanding": "x", "status": "done", '
        '"vulnerabilities": [{"vuln_type": "LFI", "endpoint": "http://x", "status": "pending"}], '
        '"attack_paths": []}'
    )
    model, err = parse_analyze_output(text)
    assert err == ""
    assert model is not None
    assert not hasattr(model, "status")
    assert not hasattr(model.vulnerabilities[0], "status")


def test_parse_analyze_output_missing_vuln_type_fails():
    text = '{"application_understanding": "x", "vulnerabilities": [{"endpoint": "http://x"}]}'
    model, err = parse_analyze_output(text)
    assert model is None
    assert "vuln_type" in err


def test_parse_analyze_output_type_error_fails():
    text = '{"application_understanding": "x", "vulnerabilities": [{"vuln_type": "SQLi", "confidence": "not-a-number"}]}'
    model, err = parse_analyze_output(text)
    assert model is None
    assert err


def test_parse_analyze_output_tool_args_string_normalized():
    text = '{"vulnerabilities": [{"vuln_type": "SSRF", "suggested_tool": "curl_get", "tool_args": "http://x"}]}'
    model, err = parse_analyze_output(text)
    assert err == ""
    assert model is not None
    assert model.vulnerabilities[0].tool_args == {"url": "http://x"}


# ── Research findings ───────────────────────────────────────────────


def test_parse_research_findings_valid():
    text = (
        '[{"vuln_type": "WeakAuth", "cve_ids": ["CVE-2020-1"], '
        '"key_techniques": ["a", "b"], "credentials_to_try": ["admin:admin"], '
        '"confidence_adjustment": 0.1}]'
    )
    models, err = parse_research_findings(text)
    assert err == ""
    assert len(models) == 1
    assert models[0].vuln_type == "WeakAuth"
    assert models[0].credentials_to_try == ["admin:admin"]
    assert models[0].confidence_adjustment == 0.1


def test_parse_research_findings_scalar_coerced_to_list():
    text = '[{"vuln_type": "SQLi", "cve_ids": "CVE-2020-1"}]'
    models, err = parse_research_findings(text)
    assert err == ""
    assert models[0].cve_ids == ["CVE-2020-1"]


def test_parse_research_findings_missing_vuln_type_fails():
    model, err = parse_research_findings('[{"cve_ids": []}]')
    assert model is None
    assert "vuln_type" in err


def test_parse_research_findings_drops_extra_fields():
    models, err = parse_research_findings('[{"vuln_type": "SQLi", "status": "done"}]')
    assert err == ""
    assert not hasattr(models[0], "status")


def test_parse_service_research_findings_valid():
    text = '[{"service": "Apache 2.4", "exploits_found": ["e1"], "cves": ["CVE-1"], "notes": "n"}]'
    models, err = parse_service_research_findings(text)
    assert err == ""
    assert models[0].service == "Apache 2.4"
    assert models[0].exploits_found == ["e1"]


def test_parse_service_research_findings_missing_service_fails():
    model, err = parse_service_research_findings('[{"cves": []}]')
    assert model is None
    assert "service" in err


# ── Plan tasks ──────────────────────────────────────────────────────


def test_parse_plan_tasks_valid():
    text = (
        '[{"id": "task-1", "instruction": "Test SQLi", "tool": "sqlmap_test", '
        '"params": {"url": "http://x", "param": "id"}, "reason": "hypothesis", '
        '"dependent_task_ids": [], "priority": 0.8}]'
    )
    models, err = parse_plan_tasks(text)
    assert err == ""
    assert len(models) == 1
    assert models[0].id == "task-1"
    assert models[0].params == {"url": "http://x", "param": "id"}
    assert models[0].priority == 0.8


def test_parse_plan_tasks_dependencies_alias():
    text = '[{"id": "t2", "instruction": "x", "dependencies": ["t1"]}]'
    models, err = parse_plan_tasks(text)
    assert err == ""
    assert models[0].dependent_task_ids == ["t1"]


def test_parse_plan_tasks_params_as_json_string():
    text = '[{"id": "t1", "instruction": "x", "params": "{\\"url\\": \\"http://x\\"}"}]'
    models, err = parse_plan_tasks(text)
    assert err == ""
    assert models[0].params == {"url": "http://x"}


def test_parse_plan_tasks_drops_status_keeps_vuln_type_and_source():
    text = (
        '[{"id": "t1", "instruction": "x", "status": "done", '
        '"vuln_type": "SQLi", "source": "credential-hint"}]'
    )
    models, err = parse_plan_tasks(text)
    assert err == ""
    assert not hasattr(models[0], "status")
    assert models[0].vuln_type == "SQLi"
    assert models[0].source == "credential-hint"


def test_parse_plan_tasks_missing_id_fails():
    model, err = parse_plan_tasks('[{"instruction": "x"}]')
    assert model is None
    assert "id" in err


def test_parse_plan_tasks_rejects_non_list():
    model, err = parse_plan_tasks('{"tasks": []}')
    assert model is None
    assert "array" in err
