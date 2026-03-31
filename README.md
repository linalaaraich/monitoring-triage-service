# monitoring-triage-service

AI-powered alert triage service for the CIRES Technologies observability platform. Receives alert webhooks from Grafana Alerting, deduplicates them, gathers context from Prometheus/Loki/Jaeger in parallel, annotates logs with Drain3 anomaly detection, and sends the context to Ollama for LLM-powered root cause analysis.

## Architecture

```
Grafana Alerting ──webhook──> POST /webhook/grafana
Drain3 background ─webhook─> POST /webhook/drain3
                                    │
                              ┌─────▼─────┐
                              │ Dedup Check│
                              └─────┬─────┘
                                    │ (not duplicate)
                         ┌──────────┼──────────┐
                         ▼          ▼          ▼
                    Prometheus    Loki      Jaeger
                      MCP        MCP        MCP
                    (:8091)    (:8092)    (:8093)
                         └──────────┬──────────┘
                                    │ (context gathered)
                              ┌─────▼─────┐
                              │Drain3 log │
                              │annotation │
                              └─────┬─────┘
                              ┌─────▼─────┐
                              │  Ollama   │
                              │  LLM RCA  │
                              └─────┬─────┘
                           ┌────────┼────────┐
                      ESCALATE           DISMISS
                      (email)            (log only)
                           └────────┬────────┘
                              Save to RCA History
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/webhook/grafana` | Grafana Alerting webhook (returns 202) |
| POST | `/webhook/drain3` | Drain3 anomaly webhook (returns 202) |
| GET | `/health` | Health check |
| GET | `/decisions` | RCA decision history (JSON) |
| GET | `/drain3/stats` | Drain3 cluster statistics |
| GET | `/metrics` | Prometheus metrics |

## Configuration

All configuration via environment variables (see `app/config.py`).

## Related

- [monitoring-project](https://github.com/linalaaraich/monitoring-project) — Ansible playbooks
- [provisioning-monitoring-infra](https://github.com/linalaaraich/provisioning-monitoring-infra) — Terraform configs
