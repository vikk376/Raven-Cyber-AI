"""Tool registry: every product Raven Cyber AI can use, in one place.

To add a built-in tool in code, create a module that calls `register(Tool(...))` and import it from
`src/tools/builtin.py`. Tools that need no code (any REST API or Logic App) are added from the UI as
targets (Containment > Targets and Tools) and show up here automatically as custom tools.
See docs/ADDING_A_TOOL.md.
"""
from collections.abc import Callable
from dataclasses import dataclass, field

CAPABILITIES = ("detect", "investigate", "hunt", "contain", "enrich", "notify", "ai", "store")
STATES = ("configured", "missing", "custom")


@dataclass(frozen=True)
class Tool:
    key: str
    name: str
    vendor: str
    category: str                      # SIEM, XDR, Identity, Network, Threat Intel, ITSM, AI, Notification, SOAR
    icon: str
    description: str
    capabilities: tuple[str, ...] = ()
    status: Callable[[], tuple[str, str]] = field(default=lambda: ("missing", ""), compare=False)
    test: Callable[[], str] | None = field(default=None, compare=False)
    nav: str | None = None             # key of the page that uses this tool


_TOOLS: dict[str, Tool] = {}


def register(tool: Tool) -> Tool:
    _TOOLS[tool.key] = tool
    return tool


def all_tools() -> list[Tool]:
    from src.tools import builtin  # noqa: F401  (registers the built-in tools on first use)
    return list(_TOOLS.values())


def get(key: str) -> Tool | None:
    all_tools()
    return _TOOLS.get(key)


def by_category() -> dict[str, list[Tool]]:
    out: dict[str, list[Tool]] = {}
    for t in all_tools():
        out.setdefault(t.category, []).append(t)
    return out


def summary() -> dict[str, int]:
    counts = {"configured": 0, "missing": 0}
    for t in all_tools():
        state, _ = t.status()
        counts[state if state in counts else "missing"] += 1
    return counts
