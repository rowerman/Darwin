"""Tool Adapter layer (P15 G5).

Each adapter owns the typed-params -> gateway-call mapping for one
capability (architecture plan section 11). The ContextResolver in
``darwin/core/capabilities.py`` dispatches to these by capability name;
capabilities without an adapter keep the legacy per-tool mapping.
"""

from darwin.tools.adapters._common import ToolAdapter
from darwin.tools.adapters.acquire_shell import AcquireShellAdapter
from darwin.tools.adapters.fetch_url import FetchUrlAdapter
from darwin.tools.adapters.test_credentials import TestCredentialsAdapter
from darwin.tools.adapters.verify_sql_injection import VerifySqlInjectionAdapter

__all__ = [
    "AcquireShellAdapter",
    "FetchUrlAdapter",
    "TestCredentialsAdapter",
    "ToolAdapter",
    "VerifySqlInjectionAdapter",
]


def default_adapters() -> list[ToolAdapter]:
    """The 4 first-round capability adapters (default tool first)."""
    return [
        FetchUrlAdapter(),
        VerifySqlInjectionAdapter(),
        TestCredentialsAdapter(),
        AcquireShellAdapter(),
    ]
