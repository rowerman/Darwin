"""fetch_url capability adapter (P15 G5)."""

from darwin.tools.adapters._common import ToolAdapter, http_post_params, passthrough


class FetchUrlAdapter(ToolAdapter):
    capability_name = "fetch_url"

    def resolve(self, env: dict, params: dict) -> dict[str, dict]:
        endpoint = env.get("endpoint", "")
        return {
            "curl_get": {"url": endpoint, **passthrough(params, ("headers", "cookie"))},
            "http_post": http_post_params(endpoint, params),
        }
