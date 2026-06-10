"""Pre-LLM metric interpreter.

Deterministic module that turns `(alert.annotations.expr, alert.values,
alert.labels)` into a structured fact bundle + a human-readable one-liner.
The LLM prompt consumes the one-liner as authoritative ground truth —
this gets the metric math OUT of the LLM's job, which was the single
biggest root cause of audit bugs #5, #6, #9 (hallucinating numbers,
ignoring observed value, conflating log-count with metric).

Design principles:
  - Never fail loudly. A missing value or unparseable PromQL returns a
    MetricFacts with partial data + a fallback one-liner. The LLM still
    gets what we have.
  - Unit detection is pattern-based on PromQL, not heuristic on the
    value. We know the 18 current rules — hardcode their patterns.
  - Threshold extraction reads the rule's threshold condition when we
    have it (via alert.annotations.threshold_* if provided, or falls
    back to parsing common patterns in the expr).
  - deployment_type comes from config.settings.service_deployment_type
    — see app/config.py for the map.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Literal

from app.config import settings
from app.llm_client import pick_primary_value


DeploymentType = Literal["k8s", "docker-vm", "systemd", "external", "unknown"]


@dataclass
class MetricFacts:
    """Pre-computed facts about an alert that the LLM can cite verbatim."""
    observed_value: float | None
    observed_ref_id: str | None
    threshold: float | None
    threshold_direction: Literal["above", "below", "at", "unknown"]
    delta: float | None                  # value - threshold (signed)
    delta_pct: float | None              # delta as % of threshold, for "X% over"
    unit: str                            # "%", "ms", "bytes/s", "boolean", or "" (unknown)
    deployment_type: DeploymentType
    one_liner: str                       # human summary — what the LLM cites
    # US-5.1 Phase C: behavioral baseline. Set by the pipeline AFTER
    # interpret() returns (interpret is sync; baselines need async
    # Prometheus). None means baseline wasn't fetched (Prometheus
    # unreachable, no service label, or thin history). When present,
    # as_prompt_block adds a "BEHAVIORAL BASELINE" line giving the LLM
    # σ-claim evidence to cite.
    baseline: object | None = None  # type: app.entity_baselines.BaselineFacts

    def as_prompt_block(self) -> str:
        """Render the facts as a prompt-ready block the LLM should cite."""
        parts = [f"OBSERVED VALUE: {self.observed_value}"]
        if self.observed_ref_id:
            parts[0] += f" (refId={self.observed_ref_id})"
        if self.unit:
            parts.append(f"UNIT: {self.unit}")
        if self.threshold is not None:
            parts.append(f"THRESHOLD: {self.threshold} ({self.threshold_direction})")
        if self.delta is not None:
            parts.append(f"DELTA: {self.delta:+.3g}" + (f" ({self.delta_pct:+.1f}%)" if self.delta_pct is not None else ""))
        parts.append(f"DEPLOYMENT TYPE: {self.deployment_type}")
        parts.append(f"INTERPRETATION: {self.one_liner}")
        # Append behavioral baseline if available — exemplar/prompt-rule J
        # tells the LLM to cite this verbatim as σ-evidence.
        if self.baseline is not None and self.observed_value is not None:
            try:
                baseline_line = self.baseline.as_prose_line(self.observed_value)
                parts.append(f"BEHAVIORAL BASELINE: {baseline_line}")
            except (AttributeError, TypeError):
                # Defensive — if baseline isn't shaped as expected, ignore.
                pass
        return "\n".join(parts)


# ---------------------------------------------------------------------------
# Unit detection
# ---------------------------------------------------------------------------

# Each tuple is (regex against PromQL, unit-name, optional-friendly-transform).
# Ordered: first match wins. Put the most specific patterns first.
_UNIT_PATTERNS: list[tuple[re.Pattern, str]] = [
    # `(expr) * 1000` where expr looks like a histogram_quantile over a _seconds_ bucket → ms
    (re.compile(r"histogram_quantile\([^)]*\)\s*(?:\*\s*1000)"), "ms"),
    # `histogram_quantile(..._seconds_bucket...)` without * 1000 → seconds
    (re.compile(r"histogram_quantile\([^)]*_seconds_bucket"), "seconds"),
    # kong_request_latency_ms bucket → already ms
    (re.compile(r"kong_request_latency_ms_bucket"), "ms"),
    # `100 - (...idle...)` CPU% idiom → percent
    (re.compile(r"100\s*-\s*\(.*mode=[\"']idle[\"']"), "percent"),
    # `(1 - avail/total) * 100` → percent (memory, disk usage pattern)
    (re.compile(r"\(\s*1\s*-\s*.*(?:avail|MemAvailable)"), "percent"),
    # `up == 0` / `up < 1` → boolean
    (re.compile(r"\bup\s*(?:==|<)\s*[01]"), "boolean"),
    # `rate(..._bytes_received_total...)` → bytes/sec
    (re.compile(r"rate\([^)]*_bytes[^)]*\)"), "bytes/sec"),
    # `predict_linear(..._avail_bytes...)` → predicted seconds-to-zero
    (re.compile(r"predict_linear\([^)]*avail_bytes"), "seconds-to-zero"),
    # otelcol dropped/accepted spans fraction → ratio (0-1 or 0-100)
    (re.compile(r"otelcol_processor_dropped_spans.*otelcol_receiver_accepted_spans"), "ratio"),
]


def detect_unit(expr: str) -> str:
    """Return the unit string for a PromQL expression, or '' if unknown."""
    if not expr:
        return ""
    for pattern, unit in _UNIT_PATTERNS:
        if pattern.search(expr):
            return unit
    return ""


# ---------------------------------------------------------------------------
# Threshold extraction
# ---------------------------------------------------------------------------

# For alerts we didn't explicitly annotate, guess the threshold from common
# PromQL idioms. This is best-effort — if we can't find it, return None and
# the LLM just gets the observed value without a delta.
_THRESHOLD_FROM_EXPR_PATTERNS: list[tuple[re.Pattern, Literal["above", "below"]]] = [
    # Common "over" thresholds implicit in expression patterns. These match
    # when the alert rule itself encodes the threshold comparison (fewer
    # of ours do — most use the 3-step Grafana form with threshold in C).
    (re.compile(r">\s*=?\s*([\d.]+)"), "above"),
    (re.compile(r"<\s*=?\s*([\d.]+)"), "below"),
    (re.compile(r"==\s*([\d.]+)"), "at"),
]


def extract_threshold(
    expr: str,
    alert_annotations: dict | None = None,
) -> tuple[float | None, Literal["above", "below", "at", "unknown"]]:
    """Pull the threshold + direction from annotations or expr parsing.

    Annotations win — if the rule author set threshold: 85 + direction: above
    in the rule annotations, use those. Otherwise parse the PromQL.
    """
    annotations = alert_annotations or {}
    # Explicit annotations
    if "threshold" in annotations:
        try:
            thr = float(annotations["threshold"])
            direction = annotations.get("threshold_direction", "above")
            if direction not in ("above", "below", "at"):
                direction = "above"
            return thr, direction  # type: ignore[return-value]
        except (TypeError, ValueError):
            pass

    # Parse from expression. Only the FIRST operator match counts — for
    # "up == 0" this gives threshold=0, direction=at.
    if expr:
        for pattern, direction in _THRESHOLD_FROM_EXPR_PATTERNS:
            m = pattern.search(expr)
            if m:
                try:
                    return float(m.group(1)), direction
                except (TypeError, ValueError):
                    pass
    return None, "unknown"


# ---------------------------------------------------------------------------
# One-liner composition
# ---------------------------------------------------------------------------

def _format_value_with_unit(v: float | None, unit: str) -> str:
    if v is None:
        return "(none)"
    if unit == "ms":
        return f"{v:.0f} ms"
    if unit == "seconds":
        return f"{v:.2f} s"
    if unit == "percent":
        return f"{v:.1f}%"
    if unit == "boolean":
        return "up" if v >= 1 else "down"
    if unit == "bytes/sec":
        # IEC-ish. Keep it simple.
        for div, suffix in ((1024**3, "GB/s"), (1024**2, "MB/s"), (1024, "KB/s")):
            if abs(v) >= div:
                return f"{v/div:.1f} {suffix}"
        return f"{v:.0f} B/s"
    if unit == "seconds-to-zero":
        if v is None or v != v:  # NaN check
            return "unknown (prediction unavailable)"
        if v < 0:
            return f"expected to fill in {abs(v/3600):.1f} h"
        return f"{v/3600:.1f} h remaining"
    if unit == "ratio":
        return f"{v*100:.2f}%" if abs(v) < 1.5 else f"{v:.2f}"
    # Unknown unit — just the raw number
    return f"{v}"


def build_one_liner(
    observed_value: float | None,
    threshold: float | None,
    direction: str,
    unit: str,
    alertname: str,
    service: str,
) -> str:
    """Compose the human-readable interpretation string.

    Examples produced:
      "CPU busy = 94.4% — 9.4pp above the 80% threshold (MediumCpuUsage, service=k3s-node)"
      "p95 latency = 1020 ms — 20 ms above the 1000 ms threshold (HighP95Latency)"
      "up = 0 (down) — target unreachable (TargetDown, service=monitoring)"
      "p95 latency = (no observed value in webhook) — (HighP95Latency)"
    """
    value_str = _format_value_with_unit(observed_value, unit)
    pieces = []
    # Lead
    if unit == "percent" and "cpu" in alertname.lower():
        lead = f"CPU busy = {value_str}"
    elif unit == "percent" and "memor" in alertname.lower():
        lead = f"Memory used = {value_str}"
    elif unit == "percent" and "disk" in alertname.lower():
        lead = f"Disk used = {value_str}"
    elif unit == "ms" and ("latenc" in alertname.lower() or "p95" in alertname.lower()):
        lead = f"p95 latency = {value_str}"
    elif unit == "boolean":
        lead = f"up = {observed_value} ({value_str})" if observed_value is not None else "up = (no observed value)"
    elif unit == "seconds-to-zero":
        lead = f"disk {value_str}"
    elif unit == "ratio":
        lead = f"dropped-span ratio = {value_str}"
    elif unit == "bytes/sec":
        lead = f"ingestion rate = {value_str}"
    else:
        lead = f"observed = {value_str}"
    pieces.append(lead)

    # Delta
    if observed_value is not None and threshold is not None:
        delta = observed_value - threshold
        if unit == "percent":
            pieces.append(f"{delta:+.1f}pp vs {threshold:g}% threshold")
        elif unit == "ms":
            pct = (delta / threshold) * 100 if threshold else 0
            pieces.append(f"{delta:+.0f} ms ({pct:+.0f}%) vs {threshold:g} ms threshold")
        elif unit == "boolean":
            pieces.append("target unreachable" if observed_value < 1 else "target responding")
        else:
            pieces.append(f"delta = {delta:+.3g} vs threshold {threshold:g}")

    # Tail: context
    pieces.append(f"({alertname}{', service=' + service if service and service != 'unknown' else ''})")

    return " — ".join(pieces)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def interpret(alert) -> MetricFacts:
    """Given a GrafanaAlert, produce a MetricFacts bundle.

    Never raises. Partial data is fine — the LLM gets what we have plus
    an interpretation string that reflects the gaps.
    """
    expr = (alert.annotations or {}).get("expr", "") or ""
    values = alert.values or {}
    service = alert.service
    alertname = alert.alertname

    observed_ref_id, observed_value = pick_primary_value(values)
    # NaN guard — some queries return NaN which is a valid float but useless
    try:
        if observed_value is not None and observed_value != observed_value:
            observed_value = None
    except TypeError:
        pass

    unit = detect_unit(expr)
    threshold, direction = extract_threshold(expr, alert.annotations)

    delta = None
    delta_pct = None
    if observed_value is not None and threshold is not None:
        delta = observed_value - threshold
        if threshold != 0:
            delta_pct = (delta / threshold) * 100

    deployment_type = settings.service_deployment_type.get(service, "unknown")
    if deployment_type == "unknown" and (
        alert.labels.get("namespace") or alert.labels.get("pod")
        or alertname.startswith("Kube") or alertname == "PodCrashLooping"
    ):
        # 2026-06-10 (iteration 4): namespace-generic k8s alerts
        # (PodCrashLooping, KubeWorkload*) fire for ANY namespace — e.g. the
        # 22 otel-demo services — but the static map only lists the
        # platform's own services, so these resolved to "unknown". That one
        # value gated out the k8s-scoped exemplars (oom-crashloop-restart
        # requires deployment_types=["k8s"]) and let the validator prune
        # kubectl actions as arch-mismatched — a structural reason the
        # PodCrashLooping RCAs hedged (decisions 7e15c8a5/2f0b5ff7) while
        # the same pod's KubeWorkloadDown named OOMKilled at 0.95. An alert
        # that carries k8s namespace/pod labels IS a k8s workload — say so.
        deployment_type = "k8s"

    one_liner = build_one_liner(
        observed_value=observed_value,
        threshold=threshold,
        direction=direction,
        unit=unit,
        alertname=alertname,
        service=service,
    )

    return MetricFacts(
        observed_value=observed_value,
        observed_ref_id=observed_ref_id,
        threshold=threshold,
        threshold_direction=direction,  # type: ignore[arg-type]
        delta=delta,
        delta_pct=delta_pct,
        unit=unit,
        deployment_type=deployment_type,  # type: ignore[arg-type]
        one_liner=one_liner,
    )
