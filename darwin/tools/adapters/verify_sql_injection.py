"""verify_sql_injection capability adapter (P15 G5)."""

from darwin.tools.adapters._common import ToolAdapter, http_post_params, passthrough


class VerifySqlInjectionAdapter(ToolAdapter):
    capability_name = "verify_sql_injection"

    def resolve(self, env: dict, params: dict) -> dict[str, dict]:
        sqlmap = {
            "url": env.get("endpoint", ""),
            "param": env.get("parameter", ""),
            **passthrough(params, ("technique", "method", "body_format", "content_type")),
        }
        return {
            "sqlmap_test": sqlmap,
            "http_post": http_post_params(env.get("endpoint", ""), params),
        }
