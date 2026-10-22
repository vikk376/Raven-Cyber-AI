"""A model tool that PROPOSES containment. It never runs anything: the analyst presses Continue on a card."""
from langchain_core.tools import tool

from src.core import constants
from src.services import indicators

MAX_PROPOSALS = 10


def make_tool(collector: list[dict], limit: int = MAX_PROPOSALS):
    @tool
    def propose_containment(action: str, value: str, justification: str = "", connector_hint: str = "") -> str:
        """Prepare ONE containment action for the analyst to confirm. Nothing is executed by this tool.
        action: ip, url, domain, device, user_disable, password_reset or custom.
        value: the IP/CIDR, URL, domain, hostname, or user principal name to act on.
        justification: why, specific to the evidence. Use the analyst's words when they gave them.
        connector_hint: optional word from the analyst's request that names the connector, such as firewall.
        Call it only when the analyst asked to block, isolate, disable or reset something."""
        cat = indicators.normalize_category(action)
        if cat not in constants.CONTAINMENT_CATEGORIES:
            return "Unknown action. Use: ip, url, domain, device, user_disable, password_reset, custom."
        ok, norm, err = indicators.validate(cat, value)
        if not ok:
            return f"Rejected: {err}"
        if cat == "ip_block":
            if indicators.is_internal_ip(norm):
                return f"Rejected: {norm} is an internal address. Do not propose blocking internal hosts; tell the analyst instead."
        if any(p["category"] == cat and p["indicator"] == norm for p in collector):
            return "Already proposed."
        if len(collector) >= limit:
            return f"Limit of {limit} proposals per answer reached. Tell the analyst to ask for the rest separately."
        collector.append({"category": cat, "indicator": norm, "reason": (justification or "").strip()[:500],
                          "connector_hint": (connector_hint or "").strip()[:40]})
        return (f"Proposed {constants.CONTAINMENT_CATEGORIES[cat][0]} for {norm}. NOT executed: the analyst must press "
                "Continue on the card. Do not say it was done.")

    return propose_containment


def make_comment_tool(collector: list[dict], limit: int = MAX_PROPOSALS):
    @tool
    def propose_incident_comment(incident_number: int, comment: str = "") -> str:
        """Prepare a Sentinel incident comment for the analyst to confirm. Nothing is posted by this tool.
        incident_number: the Sentinel incident number, for example 123. comment: the text to post.
        Call it only when the analyst asked to add a comment to an incident."""
        if not isinstance(incident_number, int) or incident_number < 1:
            return "Rejected: give the Sentinel incident number, for example 123."
        text = (comment or "").strip()[:4000]
        if any(p["category"] == "comment" and p["incident"] == incident_number and p["text"] == text for p in collector):
            return "Already proposed."
        if len(collector) >= limit:
            return f"Limit of {limit} proposals per answer reached."
        collector.append({"category": "comment", "indicator": f"incident {incident_number}", "incident": incident_number, "text": text})
        return f"Prepared a comment for incident {incident_number}. NOT posted: the analyst must press Continue. Do not say it was posted."

    return propose_incident_comment
