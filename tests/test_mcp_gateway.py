"""Tests for MCPGateway parameter normalization."""

import pytest
from darwin.tools.mcp_gateway import MCPGateway, ToolResult, _PARAM_ALIASES


class TestParamAliasesConstant:
    """The module-level _PARAM_ALIASES table."""

    def test_all_aliases_are_string_pairs(self):
        """Every entry maps a string alias to a string canonical."""
        for alias, canonical_list in _PARAM_ALIASES.items():
            assert isinstance(alias, str)
            assert isinstance(canonical_list, list), \
                f"Alias '{alias}' value must be a list, got {type(canonical_list)}"
            for c in canonical_list:
                assert isinstance(c, str)
                assert alias != c, f"Alias '{alias}' must differ from canonical '{c}'"

    def test_host_to_target_alias(self):
        assert _PARAM_ALIASES["host"] == ["target"]

    def test_url_to_target_url_alias(self):
        assert "target_url" in _PARAM_ALIASES["url"]

    def test_username_to_user_alias(self):
        assert _PARAM_ALIASES["username"] == ["user"]

    def test_pass_to_password_alias(self):
        assert _PARAM_ALIASES["pass"] == ["password"]

    def test_no_command_query_alias(self):
        """command and query are semantically different — no alias between them."""
        assert "command" not in _PARAM_ALIASES
        assert "query" not in _PARAM_ALIASES


class TestNormalizeParamsExplicitAliases:
    """Phase 1: explicit alias table remapping."""

    def test_host_remaps_to_target_when_target_in_schema(self):
        gw = MCPGateway()
        gw.register(
            name="nmap_scan",
            func=lambda target: ToolResult("nmap_scan", True, target, "", 0, 0),
            description="test",
            parameters={"target": {"type": "string"}},
        )
        # The LLM provides 'host' but the tool expects 'target'
        result = gw._normalize_params(
            "nmap_scan",
            {"host": "192.168.1.1"},
            gw._registry["nmap_scan"],
        )
        assert result == {"target": "192.168.1.1"}

    def test_host_port_composes_target(self):
        gw = MCPGateway()
        gw.register(
            name="nmap_scan",
            func=lambda target: ToolResult("nmap_scan", True, target, "", 0, 0),
            description="test",
            parameters={"target": {"type": "string"}},
        )
        result = gw._normalize_params(
            "nmap_scan",
            {"host": "dbhost", "port": 3306},
            gw._registry["nmap_scan"],
        )
        assert result == {"target": "dbhost:3306"}

    def test_url_remaps_to_target_url_when_target_url_in_schema(self):
        gw = MCPGateway()
        gw.register(
            name="dirb_scan",
            func=lambda target_url: ToolResult("dirb_scan", True, target_url, "", 0, 0),
            description="test",
            parameters={"target_url": {"type": "string"}},
        )
        result = gw._normalize_params(
            "dirb_scan",
            {"url": "http://example.com"},
            gw._registry["dirb_scan"],
        )
        assert result == {"target_url": "http://example.com"}

    def test_username_remaps_to_user_when_user_in_schema(self):
        gw = MCPGateway()
        gw.register(
            name="mysql_query",
            func=lambda host, port, user, password, query: ToolResult(
                "mysql_query", True, "", "", 0, 0,
            ),
            description="test",
            parameters={
                "host": {"type": "string"},
                "port": {"type": "integer"},
                "user": {"type": "string"},
                "password": {"type": "string"},
                "query": {"type": "string"},
            },
        )
        result = gw._normalize_params(
            "mysql_query",
            {"host": "db", "port": 3306, "username": "admin", "password": "x", "query": "SELECT 1"},
            gw._registry["mysql_query"],
        )
        assert result["user"] == "admin"
        assert "username" not in result
        assert result["host"] == "db"

    def test_pass_remaps_to_password(self):
        gw = MCPGateway()
        gw.register(
            name="test_tool",
            func=lambda host, password: ToolResult("x", True, "", "", 0, 0),
            description="test",
            parameters={
                "host": {"type": "string"},
                "password": {"type": "string"},
            },
        )
        result = gw._normalize_params(
            "test_tool",
            {"host": "x", "pass": "secret"},
            gw._registry["test_tool"],
        )
        assert result["password"] == "secret"
        assert "pass" not in result

    def test_alias_not_applied_when_canonical_already_provided(self):
        """If the LLM provides both alias and canonical, canonical wins."""
        gw = MCPGateway()
        gw.register(
            name="nmap_scan",
            func=lambda target: ToolResult("nmap_scan", True, target, "", 0, 0),
            description="test",
            parameters={"target": {"type": "string"}},
        )
        result = gw._normalize_params(
            "nmap_scan",
            {"host": "badhost", "target": "192.168.1.1"},
            gw._registry["nmap_scan"],
        )
        # canonical 'target' was already provided — alias NOT applied
        assert result["target"] == "192.168.1.1"

    def test_alias_not_applied_when_canonical_not_in_schema(self):
        """No alias when the tool doesn't declare the canonical param."""
        gw = MCPGateway()
        gw.register(
            name="ssh_exec",
            func=lambda host, command: ToolResult("ssh_exec", True, "", "", 0, 0),
            description="test",
            parameters={
                "host": {"type": "string"},
                "command": {"type": "string"},
            },
        )
        # 'host'→'target' alias: canonical 'target' not in schema → skip
        # 'username'→'user' alias: canonical 'user' not in schema → skip
        result = gw._normalize_params(
            "ssh_exec",
            {"host": "10.0.0.1", "username": "root", "command": "id"},
            gw._registry["ssh_exec"],
        )
        assert result["host"] == "10.0.0.1"
        assert result["command"] == "id"
        # 'username' dropped because 'user' not in schema and substring
        # matching won't match 'username' to any declared param


class TestNormalizeParamsAnonymous:
    """Phase 2: anonymous flag → empty credentials."""

    def test_anonymous_populates_empty_user_password(self):
        gw = MCPGateway()
        gw.register(
            name="test_tool",
            func=lambda host, user, password: ToolResult("x", True, "", "", 0, 0),
            description="test",
            parameters={
                "host": {"type": "string"},
                "user": {"type": "string"},
                "password": {"type": "string"},
            },
        )
        result = gw._normalize_params(
            "test_tool",
            {"host": "x", "anonymous": True},
            gw._registry["test_tool"],
        )
        assert result["user"] == ""
        assert result["password"] == ""

    def test_anonymous_does_not_overwrite_existing_credentials(self):
        gw = MCPGateway()
        gw.register(
            name="test_tool",
            func=lambda host, user, password: ToolResult("x", True, "", "", 0, 0),
            description="test",
            parameters={
                "host": {"type": "string"},
                "user": {"type": "string"},
                "password": {"type": "string"},
            },
        )
        result = gw._normalize_params(
            "test_tool",
            {"host": "x", "user": "admin", "password": "realpw", "anonymous": True},
            gw._registry["test_tool"],
        )
        assert result["user"] == "admin"
        assert result["password"] == "realpw"


class TestNormalizeParamsSubstringFuzzy:
    """Phase 3: substring fuzzy matching."""

    def test_direction1_declared_param_is_substring_of_provided(self):
        """declared 'url' ⊂ provided 'target_url' → match."""
        gw = MCPGateway()
        gw.register(
            name="curl_get",
            func=lambda url: ToolResult("curl_get", True, url, "", 0, 0),
            description="test",
            parameters={"url": {"type": "string"}},
        )
        result = gw._normalize_params(
            "curl_get",
            {"target_url": "http://example.com"},
            gw._registry["curl_get"],
        )
        assert result == {"url": "http://example.com"}

    def test_direction2_provided_is_substring_of_declared(self):
        """provided 'url' ⊂ declared 'target_url' → match (3 ≥ 3 and 3 ≥ 40%×10=4? No, 3<4).
        Wait — 3 < 4 so it won't match via substring. Let me check...
        Actually 'url' is 3 chars, 'target_url' is 10. 40% of 10 = 4. 3 < 4 → fails threshold.
        BUT this case is covered by the explicit alias 'url'→'target_url' in Phase 1,
        so it's fine. Let me test a case that DOES pass the threshold."""
        gw = MCPGateway()
        gw.register(
            name="test_tool",
            func=lambda service_name: ToolResult("x", True, "", "", 0, 0),
            description="test",
            parameters={"service_name": {"type": "string"}},
        )
        # 'service' is 7 chars, 'service_name' is 12. 40% × 12 = 4.8. 7 ≥ 4.8 → match
        result = gw._normalize_params(
            "test_tool",
            {"service": "http"},
            gw._registry["test_tool"],
        )
        assert result == {"service_name": "http"}

    def test_ambiguous_substring_no_match(self):
        """When multiple candidates exist, no match — avoids guessing wrong."""
        gw = MCPGateway()
        gw.register(
            name="test_tool",
            func=lambda url: ToolResult("x", True, "", "", 0, 0),
            description="test",
            parameters={"url": {"type": "string"}},
        )
        result = gw._normalize_params(
            "test_tool",
            {"base_url": "x", "target_url": "y"},
            gw._registry["test_tool"],
        )
        # Both 'base_url' and 'target_url' contain 'url' → ambiguous → no match
        assert "url" not in result

    def test_complex_cascade_phase1_then_phase3(self):
        """Ensure Phase 1 aliases don't interfere with Phase 3 matching."""
        gw = MCPGateway()
        gw.register(
            name="test_tool",
            func=lambda url, param: ToolResult("x", True, "", "", 0, 0),
            description="test",
            parameters={
                "url": {"type": "string"},
                "param": {"type": "string"},
            },
        )
        # 'ssrf_url' → 'target_url' alias tries to map to 'target_url' but tool
        # doesn't have 'target_url'. However 'ssrf_url' contains 'url' (declared),
        # so Phase 3 Direction 1 should match: declared 'url' ⊂ provided 'ssrf_url'
        result = gw._normalize_params(
            "test_tool",
            {"ssrf_url": "http://x.com", "param": "id"},
            gw._registry["test_tool"],
        )
        # Phase 1: alias 'ssrf_url'→'target_url' — but 'target_url' NOT in schema → skip
        # Phase 3: declared 'url' is substring of provided 'ssrf_url' → match!
        assert result["url"] == "http://x.com"
        assert result["param"] == "id"


class TestNormalizeParamsDropExtras:
    """Phase 4: drop params not in the tool's declared schema."""

    def test_extra_params_dropped(self):
        gw = MCPGateway()
        gw.register(
            name="test_tool",
            func=lambda host: ToolResult("x", True, host, "", 0, 0),
            description="test",
            parameters={"host": {"type": "string"}},
        )
        result = gw._normalize_params(
            "test_tool",
            {"host": "x", "extra_field": "should_drop", "another": 123},
            gw._registry["test_tool"],
        )
        assert result == {"host": "x"}

    def test_all_valid_params_kept(self):
        gw = MCPGateway()
        gw.register(
            name="test_tool",
            func=lambda a, b, c: ToolResult("x", True, "", "", 0, 0),
            description="test",
            parameters={
                "a": {"type": "string"},
                "b": {"type": "string"},
                "c": {"type": "string"},
            },
        )
        result = gw._normalize_params(
            "test_tool",
            {"a": "1", "b": "2", "c": "3"},
            gw._registry["test_tool"],
        )
        assert result == {"a": "1", "b": "2", "c": "3"}


class TestNormalizeParamsBackwardCompatibility:
    """Ensure existing correct calls are unchanged."""

    def test_correct_params_unchanged(self):
        gw = MCPGateway()
        gw.register(
            name="send_payload",
            func=lambda url, param, payload, method: ToolResult("x", True, "", "", 0, 0),
            description="test",
            parameters={
                "url": {"type": "string"},
                "param": {"type": "string"},
                "payload": {"type": "string"},
                "method": {"type": "string"},
            },
        )
        result = gw._normalize_params(
            "send_payload",
            {"url": "http://x.com", "param": "id", "payload": "x", "method": "GET"},
            gw._registry["send_payload"],
        )
        assert result == {"url": "http://x.com", "param": "id", "payload": "x", "method": "GET"}

    def test_command_not_aliased_to_query(self):
        """ssh_exec expects 'command', not 'query'. No false alias."""
        gw = MCPGateway()
        gw.register(
            name="ssh_exec",
            func=lambda host, username, password, command: ToolResult(
                "ssh_exec", True, "", "", 0, 0,
            ),
            description="test",
            parameters={
                "host": {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "command": {"type": "string"},
            },
        )
        result = gw._normalize_params(
            "ssh_exec",
            {"host": "10.0.0.1", "username": "root", "password": "x", "command": "id"},
            gw._registry["ssh_exec"],
        )
        assert result["command"] == "id"
        assert "query" not in result


class TestCallWithNormalization:
    """Integration: gateway.call() applies normalization before dispatch."""

    @pytest.mark.asyncio
    async def test_call_normalizes_host_to_target(self):
        gw = MCPGateway()
        gw.register(
            name="nmap_scan",
            func=lambda target: ToolResult("nmap_scan", True, f"scanned {target}", "", 0, 0),
            description="test",
            parameters={"target": {"type": "string"}},
        )
        result = await gw.call("nmap_scan", {"host": "10.0.0.1"})
        assert result.success
        assert "10.0.0.1" in result.stdout

    @pytest.mark.asyncio
    async def test_call_normalizes_username_to_user(self):
        gw = MCPGateway()
        async def _db(host, user, password):
            return ToolResult("db", True, f"connected as {user}", "", 0, 0)
        gw.register(
            name="db_tool",
            func=_db,
            description="test",
            parameters={
                "host": {"type": "string"},
                "user": {"type": "string"},
                "password": {"type": "string"},
            },
        )
        result = await gw.call("db_tool", {
            "host": "db", "username": "admin", "password": "secret",
        })
        assert result.success
        assert "admin" in result.stdout

    @pytest.mark.asyncio
    async def test_call_extra_params_dropped(self):
        gw = MCPGateway()
        def _sync(host):
            return ToolResult("x", True, f"host={host}", "", 0, 0)
        gw.register(
            name="sync_tool",
            func=_sync,
            description="test",
            parameters={"host": {"type": "string"}},
        )
        # LLM adds extra params that the tool doesn't need
        result = await gw.call("sync_tool", {"host": "x", "unused": "junk"})
        assert result.success

    @pytest.mark.asyncio
    async def test_call_unknown_tool_returns_error(self):
        gw = MCPGateway()
        result = await gw.call("nonexistent", {})
        assert not result.success
        assert "not found" in result.stderr

    @pytest.mark.asyncio
    async def test_call_tool_raises_exception_gracefully(self):
        gw = MCPGateway()
        async def _bad(**kwargs):
            raise RuntimeError("simulated crash")
        gw.register(
            name="crashy",
            func=_bad,
            description="test",
            parameters={},
        )
        result = await gw.call("crashy", {})
        assert not result.success
        assert "simulated crash" in result.stdout
