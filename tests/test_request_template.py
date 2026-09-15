"""One request shape, rendered by whichever tool is asked to send it."""

from __future__ import annotations

import json

from darwin.tools.request_template import (
    InjectSlot,
    RequestTemplate,
    tools_for_request,
)


def _json_post_template() -> RequestTemplate:
    return RequestTemplate(
        url="http://t/workflows",
        method="POST",
        content_type="application/json",
        body_format="json",
        inject=InjectSlot("body", "dataset_ref"),
        payload="../../etc/passwd",
    )


def test_route_declaration_wins_over_the_tool_default():
    """A documented POST route is never tested with the tool's default GET."""
    template = RequestTemplate.derive(
        "send_payload",
        {"url": "http://t/workflows", "param": "dataset_ref",
         "payload": "../../etc/passwd"},
        documented_methods={"POST"},
    )

    assert template is not None
    assert template.method == "POST"
    assert template.body_format == "json"


def test_a_planned_verb_the_route_contradicts_is_corrected():
    template = RequestTemplate.derive(
        "send_payload",
        {"url": "http://t/workflows", "method": "GET", "param": "x", "payload": "y"},
        documented_methods={"POST"},
    )

    assert template is not None and template.method == "POST"


def test_json_body_renders_into_send_payload():
    params = _json_post_template().render("../tenant-b/secret.txt").tool_params(
        "send_payload",
    )

    assert params["method"] == "POST"
    assert params["body_format"] == "json"
    assert json.loads(params["payload"]) == {
        "dataset_ref": "../tenant-b/secret.txt",
    }


def test_json_body_renders_into_http_post():
    params = _json_post_template().tool_params("http_post")

    assert params["method"] == "POST"
    assert params["content_type"] == "application/json"
    assert json.loads(params["data"])["dataset_ref"] == "../../etc/passwd"


def test_get_only_renderer_is_refused_for_a_write_route():
    """A tool that cannot express the request says so instead of guessing."""
    assert _json_post_template().tool_params("curl_get") is None


def test_ssti_tool_cannot_carry_a_json_body():
    """It used to be handed a JSON plan and silently send a form body."""
    assert _json_post_template().tool_params("ssti_inject") is None


def test_form_template_is_expressible_by_the_form_tools():
    form = RequestTemplate(
        url="http://t/login", method="POST", body_format="form",
        inject=InjectSlot("body", "user"), payload="admin",
    )

    assert form.tool_params("ssti_inject")["param_name"] == "user"
    assert form.tool_params("command_injection_test")["param"] == "user"
    assert form.tool_params("curl_get") is None


def test_query_template_renders_into_the_query_string():
    query = RequestTemplate(
        url="http://t/search", method="GET",
        inject=InjectSlot("query", "q"), payload="a b",
    )

    assert query.tool_params("curl_get")["url"] == "http://t/search?q=a%20b"


def test_tool_selection_follows_verb_and_body_shape():
    assert "http_post" in tools_for_request({"POST"}, body_format="json")
    assert "curl_get" not in tools_for_request({"POST"}, body_format="json")
    assert tools_for_request({"GET"}, body_format="none")[0] == "curl_get"


def test_template_survives_a_round_trip_through_the_task_action():
    original = _json_post_template()

    restored = RequestTemplate.from_dict(original.to_dict())

    assert restored == original


def test_task_keeps_the_template_so_later_hops_render_the_same_request():
    """The verb the route declared is stored with the task, not re-guessed."""
    from darwin.core.contracts import TaskStatus
    from darwin.core.task import Task
    from darwin.orchestration.execution import ExecutionCoordinator

    class _DKG:
        def query_nodes(self, node_type=None, filters=None, **_kw):
            if node_type != "Endpoint":
                return []
            return [{"id": "ep-1", "url": "http://t/workflows", "method": "POST",
                     "allow_methods": "POST, OPTIONS"}]

    orch = type("Orch", (), {"dkg": _DKG()})()
    coord = ExecutionCoordinator.__new__(ExecutionCoordinator)
    object.__setattr__(coord, "_orch", orch)
    task = Task(
        id="t1", type="task", goal="g", instruction="traverse",
        action={"tool": "send_payload",
                "params": {"url": "http://t/workflows", "method": "GET",
                           "param": "dataset_ref", "payload": "../secret"}},
        status=TaskStatus.READY,
    )

    params = coord._apply_request_template(
        "send_payload", dict(task.action["params"]), task=task,
    )

    assert task.action["request"]["method"] == "POST"
    assert task.action["request"]["body_format"] == "json"
    assert params["method"] == "POST"
    assert params["body_format"] == "json"
    assert json.loads(params["payload"]) == {"dataset_ref": "../secret"}


def test_every_renderer_agrees_with_the_tool_contract_it_targets():
    """A renderer that spells a parameter the tool does not declare silently
    drops the request's target once the call is projected onto that tool."""
    from darwin.tools.attack_server import create_attack_gateway
    from darwin.tools.recon_server import create_recon_gateway
    from darwin.tools.request_template import REQUEST_RENDERERS

    specs: dict = {}
    for gateway in (create_attack_gateway(), create_recon_gateway()):
        specs.update(gateway.get_tool_specs())
    templates = {
        "json": _json_post_template(),
        "form": RequestTemplate(
            url="http://t/login", method="POST", body_format="form",
            inject=InjectSlot("body", "user"), payload="admin",
        ),
        "query": RequestTemplate(
            url="http://t/search", method="GET",
            inject=InjectSlot("query", "q"), payload="a",
        ),
    }
    for tool in REQUEST_RENDERERS:
        declared = dict(specs[tool].parameters) if tool in specs else {}
        assert declared, f"{tool} has no registered contract"
        for label, template in templates.items():
            rendered = template.tool_params(tool, declared)
            if rendered is None:
                continue
            assert set(rendered) <= set(declared), (
                f"{tool}/{label} renders undeclared keys: "
                f"{sorted(set(rendered) - set(declared))}"
            )
            target = (
                rendered.get("url") or rendered.get("target_url")
                or rendered.get("ssrf_url") or ""
            )
            assert str(target).startswith(template.url), (tool, label, rendered)
