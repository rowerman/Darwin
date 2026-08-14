"""test_credentials capability adapter (P15 G5)."""

from darwin.tools.adapters._common import ToolAdapter, passthrough


class TestCredentialsAdapter(ToolAdapter):
    capability_name = "test_credentials"

    def resolve(self, env: dict, params: dict) -> dict[str, dict]:
        cred = env.get("credential") if isinstance(env.get("credential"), dict) else {}
        return {
            "test_credential": {
                "user": env.get("username", "root"),
                "password": str(cred.get("password") or ""),
                "host": str(cred.get("host") or ""),
                "port": env.get("port", 22),
                "command": env.get("command", "id"),
            },
            "hydra_http_brute": {
                "url": env.get("endpoint", ""),
                **passthrough(params, ("userlist", "passlist")),
            },
        }
