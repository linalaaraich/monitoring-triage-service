"""Action-template selector + placeholder filler.

When the LLM's `suggested_actions` is empty (or gets rejected by the
response validator for being all-vague), the pipeline consults these
templates. Keyed by alertname regex pattern, branched by deployment type,
filled with real labels from the firing alert.

This was the single biggest win against audit bug #7 (empty
suggested_actions on nearly every row). The LLM now has to compete with
a reliable fallback — it either produces something better or the
template ships.

See app/suggested_actions.yaml for the template rules themselves.
"""
from __future__ import annotations

import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.config import settings

logger = logging.getLogger(__name__)

_TEMPLATE_PATH = Path(__file__).parent / "suggested_actions.yaml"


@lru_cache(maxsize=1)
def _load_rules() -> list[dict[str, Any]]:
    """Load the YAML once; memoize. If the file is missing or malformed,
    return an empty list — template fill silently no-ops."""
    if not _TEMPLATE_PATH.exists():
        logger.warning("suggested_actions.yaml not found at %s — template fill disabled", _TEMPLATE_PATH)
        return []
    try:
        with _TEMPLATE_PATH.open() as f:
            data = yaml.safe_load(f) or {}
        rules = data.get("rules", [])
        # Pre-compile regex patterns
        for r in rules:
            if "match" in r:
                try:
                    r["_compiled"] = re.compile(r["match"])
                except re.error as e:
                    logger.warning("Invalid regex in suggested_actions.yaml: %r (%s)", r["match"], e)
                    r["_compiled"] = None
        logger.info("Loaded %d action-template rules from %s", len(rules), _TEMPLATE_PATH)
        return rules
    except Exception as exc:
        logger.error("Failed to parse suggested_actions.yaml: %s", exc)
        return []


def _format_host(instance: str | None) -> str:
    """Turn '10.0.1.194:9100' into 'observability-rca-k3s' using the
    existing settings.instance_hosts map. Returns the raw IP if no match."""
    if not instance:
        return "<host-unknown>"
    ip = instance.split(":", 1)[0]
    return settings.instance_hosts.get(ip, ip)


def fill_template(
    alertname: str,
    service: str,
    deployment_type: str,
    labels: dict[str, str],
) -> list[str]:
    """Look up the first matching rule for alertname, pick the
    deployment_type-scoped action list, and substitute placeholders.

    Returns [] if no rule matches or if the deployment_type's list is empty.
    Never raises; malformed templates log + skip.
    """
    rules = _load_rules()
    for r in rules:
        compiled = r.get("_compiled")
        if compiled is None:
            continue
        if not compiled.search(alertname):
            continue

        by_dt = r.get("by_deployment_type", {})
        # Fall back to 'unknown' if the specific deployment_type is missing
        actions = by_dt.get(deployment_type) or by_dt.get("unknown") or []
        if not actions:
            return []

        # Placeholder substitution. Keep the set small — instance,
        # instance_host, service, grafana_url, and whatever labels the
        # rule matched against.
        subs = {
            "instance": labels.get("instance", "<instance-unknown>"),
            "instance_host": _format_host(labels.get("instance")),
            "service": service,
            "grafana": settings.grafana_url,
            "job": labels.get("job", ""),
        }
        filled = []
        for a in actions:
            try:
                filled.append(a.format(**subs))
            except KeyError as e:
                logger.warning("Template placeholder %s missing for alert %s", e, alertname)
                filled.append(a)  # emit raw placeholder rather than drop the action
            except Exception as e:
                logger.warning("Template fill failed for alert %s: %s", alertname, e)
        return filled

    return []


# Public symbol for tests
__all__ = ["fill_template"]
