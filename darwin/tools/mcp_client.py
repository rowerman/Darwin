"""Real MCP (Model Context Protocol) client — stdio transport.

Connects to external MCP servers over stdio, discovers their tools
via tools/list, and proxies tool calls via tools/call.

Protocol: JSON-RPC 2.0 over stdio, Content-Length framed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger(__name__)


@dataclass
class MCPServerConfig:
    """Configuration for one MCP server connection."""
    name: str
    command: str          # executable (e.g. "npx", "python3")
    args: List[str] = field(default_factory=list)  # command args
    env: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True


@dataclass
class MCPToolDef:
    """An MCP tool definition, compatible with OpenAI function calling."""
    name: str
    description: str
    input_schema: Dict[str, Any] = field(default_factory=dict)
    server_name: str = ""


class MCPClient:
    """Client for one MCP server over stdio transport.

    Spawns the server process, performs the initialize handshake,
    discovers tools, and proxies tool calls.
    """

    def __init__(self, config: MCPServerConfig, connect_timeout: float = 30.0):
        self.config = config
        self.connect_timeout = connect_timeout
        self.request_timeout = max(connect_timeout, 120.0)
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._request_id = 0
        self._pending: Dict[int, asyncio.Future] = {}
        self._reader_task: Optional[asyncio.Task] = None
        self._buf = b""
        self._initialized = False
        self._tools: Dict[str, MCPToolDef] = {}

    # ── Lifecycle ─────────────────────────────────────────────────

    async def start(self) -> None:
        """Spawn the MCP server and perform initialize handshake."""
        env = os.environ.copy()
        env.update(self.config.env)

        self._proc = await asyncio.create_subprocess_exec(
            self.config.command,
            *self.config.args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        self._reader_task = asyncio.create_task(self._read_loop())

        # MCP initialize handshake
        result = await self._request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "DARWIN", "version": "0.1.0"},
        })
        server_info = result.get("serverInfo", {})
        log.info("MCP server '%s' (%s %s) connected",
                 self.config.name,
                 server_info.get("name", "unknown"),
                 server_info.get("version", ""))

        # Send initialized notification
        await self._notify("initialized", {})

        # Discover tools
        tools_result = await self._request("tools/list", {})
        for t in tools_result.get("tools", []):
            self._tools[t["name"]] = MCPToolDef(
                name=t["name"],
                description=t.get("description", ""),
                input_schema=t.get("inputSchema", {}),
                server_name=self.config.name,
            )

        self._initialized = True
        log.info("MCP server '%s': discovered %d tools", self.config.name, len(self._tools))

    async def stop(self) -> None:
        """Terminate the MCP server process."""
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
        if self._proc:
            try:
                self._proc.stdin.close()
            except Exception:
                pass
            try:
                self._proc.terminate()
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._proc.kill()
                await self._proc.wait()
            except Exception:
                pass
        self._initialized = False

    # ── Tool Discovery ────────────────────────────────────────────

    def get_tools(self) -> List[MCPToolDef]:
        """Get all discovered tools."""
        return list(self._tools.values())

    def get_tool(self, name: str) -> Optional[MCPToolDef]:
        """Get a specific tool definition."""
        return self._tools.get(name)

    # ── Tool Execution ────────────────────────────────────────────

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an MCP tool and return its result."""
        if name not in self._tools:
            raise ValueError(f"MCP tool '{name}' not found on server '{self.config.name}'")
        result = await self._request("tools/call", {
            "name": name,
            "arguments": arguments,
        })
        return result

    # ── JSON-RPC Transport ────────────────────────────────────────

    async def _request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Send a JSON-RPC request and await the response."""
        self._request_id += 1
        rid = self._request_id
        msg = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
        future: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending[rid] = future

        await self._send(msg)

        try:
            return await asyncio.wait_for(future, timeout=self.request_timeout)
        except asyncio.TimeoutError:
            self._pending.pop(rid, None)
            raise

    async def _notify(self, method: str, params: Dict[str, Any]) -> None:
        """Send a JSON-RPC notification (no response expected)."""
        msg = {"jsonrpc": "2.0", "method": method, "params": params}
        await self._send(msg)

    async def _send(self, msg: Dict[str, Any]) -> None:
        """Send a JSON-RPC message to the server's stdin (line-delimited)."""
        if not self._proc or not self._proc.stdin:
            raise RuntimeError(f"MCP server '{self.config.name}' not running")
        body = json.dumps(msg, ensure_ascii=False)
        self._proc.stdin.write((body + "\n").encode("utf-8"))
        await self._proc.stdin.drain()

    async def _read_loop(self) -> None:
        """Continuously read JSON-RPC messages from server's stdout."""
        if not self._proc or not self._proc.stdout:
            return
        try:
            while True:
                msg = await self._read_message()
                if msg is None:
                    break
                await self._handle_message(msg)
        except asyncio.CancelledError:
            return
        except Exception as e:
            log.warning("MCP reader for '%s' error: %s", self.config.name, e)

    async def _read_message(self) -> Optional[Dict[str, Any]]:
        """Read one JSON-RPC message (supports both framed and line-delimited)."""
        if not self._proc or not self._proc.stdout:
            return None

        # Read first line to determine transport format
        first_line = await self._proc.stdout.readline()
        if not first_line:
            return None
        first_str = first_line.decode("utf-8", errors="replace").rstrip("\r\n")

        # Line-delimited JSON (raw JSON per line, no framing)
        if first_str.startswith("{"):
            try:
                return json.loads(first_str)
            except json.JSONDecodeError:
                return None

        # Content-Length framed protocol
        content_length = 0
        if first_str.lower().startswith("content-length:"):
            try:
                content_length = int(first_str.split(":", 1)[1].strip())
            except ValueError:
                pass

        if content_length > 0:
            # Read remaining headers until empty line
            while True:
                line = await self._proc.stdout.readline()
                if not line:
                    return None
                line = line.decode("utf-8", errors="replace").rstrip("\r\n")
                if line == "":
                    break
                if line.lower().startswith("content-length:"):
                    try:
                        content_length = int(line.split(":", 1)[1].strip())
                    except ValueError:
                        pass

        if content_length <= 0:
            return None

        body_bytes = await self._proc.stdout.readexactly(content_length)
        body = json.loads(body_bytes.decode("utf-8"))
        return body

    async def _handle_message(self, msg: Dict[str, Any]) -> None:
        """Handle an incoming JSON-RPC message."""
        rid = msg.get("id")
        if rid is not None and "method" not in msg:
            # It's a response to one of our requests
            future = self._pending.pop(rid, None)
            if future and not future.done():
                if "error" in msg:
                    future.set_exception(
                        RuntimeError(f"MCP error: {msg['error'].get('message', 'unknown')}")
                    )
                else:
                    future.set_result(msg.get("result", {}))
        # Notifications from server are ignored for now


class MCPClientPool:
    """Manages connections to multiple MCP servers.

    Aggregates tools from all connected servers and routes tool calls
    to the correct server.
    """

    def __init__(self):
        self._clients: Dict[str, MCPClient] = {}
        self._tool_to_server: Dict[str, str] = {}  # tool_name -> server_name

    @property
    def is_connected(self) -> bool:
        return len(self._clients) > 0

    async def connect_all(self, configs: List[MCPServerConfig],
                          per_server_timeout: float = 15.0,
                          total_timeout: float = 10.0) -> int:
        """Connect to all enabled MCP servers in parallel.

        Each server gets per_server_timeout to complete its handshake.
        The overall call returns after total_timeout with whatever servers
        connected so far. Unfinished connection attempts are cancelled.

        Returns:
            Number of servers successfully connected.
        """
        enabled = [c for c in configs if c.enabled]
        if not enabled:
            return 0

        async def _connect_one(cfg: MCPServerConfig) -> str | None:
            try:
                client = MCPClient(cfg, connect_timeout=per_server_timeout)
                await asyncio.wait_for(client.start(), timeout=per_server_timeout)
                self._clients[cfg.name] = client
                for tool in client.get_tools():
                    self._tool_to_server[tool.name] = cfg.name
                log.info("MCP '%s': %d tools", cfg.name, len(client.get_tools()))
                return cfg.name
            except asyncio.TimeoutError:
                log.info("MCP '%s': timed out after %.0fs", cfg.name, per_server_timeout)
                return None
            except Exception as e:
                log.info("MCP '%s': %s", cfg.name, e)
                return None

        # Run all connections in parallel
        tasks = [asyncio.create_task(_connect_one(cfg)) for cfg in enabled]
        try:
            done, pending = await asyncio.wait(tasks, timeout=total_timeout)
            # Cancel still-pending tasks
            for t in pending:
                t.cancel()
            # Let cancellations propagate
            for t in pending:
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass
        except Exception:
            for t in tasks:
                t.cancel()

        connected = len(self._clients)
        if connected > 0 and connected < len(enabled):
            log.info("MCP: %d/%d servers connected (continuing without the rest)",
                     connected, len(enabled))
        return connected

    async def disconnect_all(self) -> None:
        """Stop all MCP server connections."""
        for name, client in list(self._clients.items()):
            try:
                await client.stop()
            except Exception as e:
                log.debug("Error stopping MCP server '%s': %s", name, e)
        self._clients.clear()
        self._tool_to_server.clear()

    def get_all_tools(self) -> List[MCPToolDef]:
        """Get tools from all connected servers."""
        tools: List[MCPToolDef] = []
        for client in self._clients.values():
            tools.extend(client.get_tools())
        return tools

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Get all tools as OpenAI function-calling definitions."""
        defs = []
        for tool in self.get_all_tools():
            props = tool.input_schema.get("properties", {})
            defs.append({
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": {
                        "type": "object",
                        "properties": props,
                        "required": tool.input_schema.get("required", list(props.keys())),
                    },
                },
            })
        return defs

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Route a tool call to the correct MCP server."""
        server_name = self._tool_to_server.get(name)
        if not server_name:
            raise ValueError(f"No MCP server provides tool '{name}'")
        client = self._clients.get(server_name)
        if not client:
            raise RuntimeError(f"MCP server '{server_name}' not connected")
        return await client.call_tool(name, arguments)

    def get_tool_names(self) -> List[str]:
        return list(self._tool_to_server.keys())


def load_mcp_config(config_path: str = "config/mcp_servers.yaml") -> List[MCPServerConfig]:
    """Load MCP server configurations from a YAML file."""
    if not os.path.exists(config_path):
        log.info("No MCP servers config found at %s", config_path)
        return []

    import yaml
    with open(config_path) as f:
        data = yaml.safe_load(f)

    servers = []
    for name, cfg in data.get("servers", {}).items():
        servers.append(MCPServerConfig(
            name=name,
            command=cfg.get("command", ""),
            args=cfg.get("args", []),
            env=cfg.get("env", {}),
            enabled=cfg.get("enabled", True),
        ))
    return servers
