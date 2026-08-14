"""acquire_shell capability adapter (P15 G5)."""

from darwin.tools.adapters._common import ToolAdapter


class AcquireShellAdapter(ToolAdapter):
    capability_name = "acquire_shell"

    def resolve(self, env: dict, params: dict) -> dict[str, dict]:
        cred = env.get("credential") if isinstance(env.get("credential"), dict) else {}
        host = str(cred.get("host") or "")
        port = env.get("port", 22)
        command = env.get("command", "id")
        username = env.get("username", "root")
        return {
            "ssh_exec": {
                "host": host,
                "port": port,
                "username": username,
                "password": str(cred.get("password") or ""),
                "command": command,
            },
            "ssh_key_exec": {
                "key_path": str(
                    cred.get("key_path") or params.get("key_path") or "~/.ssh/id_rsa"
                ),
                "user": username,
                "host": host,
                "port": port,
                "command": command,
            },
            "shell_exec": {"command": command},
        }
