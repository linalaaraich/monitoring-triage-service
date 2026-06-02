# Frontend Audit — 2026-06-02

Comprehensive audit of every clickable element on the CIRES triage dashboard.
Scope: `/dashboard`, `/dashboard/kpi`, `/dashboard/services`, `/dashboard/alerts`,
`/dashboard/alert/{id}`, `/dashboard/alert/{id}/rate`, and the React sidebar.

## Severity legend

- **P0** — broken: dead link, 404, no-op handler, full-page jump where partial
  refresh was expected, layout breaks usability.
- **P1** — bad UX: works but confusing, stub instead of real data, hardcoded
  placeholder, redirects to the feed instead of showing relevant content.
- **P2** — polish: cosmetic, copy-edits, hover states, minor consistency.

## Summary

- Total findings: 28
- P0: 9 (fixed inline this pass)
- P1: 13 (deferred to Sprint 5)
- P2: 6 (deferred to Sprint 5)

---

## /dashboard (triage feed)

| # | Element | Current state | Expected | Severity | Fix |
|---|---|---|---|---|---|
| 1 | `<meta http-equiv="refresh" content="60">` | Hard reload every 60s — loses scroll, expanded row, filter focus | Partial fetch swap | **P0** | Replace with setInterval(60s) -> fetch `/dashboard?_partial=1`, swap React state |
| 2 | Top-bar / no refresh indicator | Operator has no signal the data is auto-refreshing | Tiny "refreshing..." pip + last-updated timestamp | **P0** | Add `<span id="cires-refresh-indicator">` in top-bar |
| 3 | Body / viewport fill | No `html, body { min-height: 100vh }` -> on tall monitors a gap appeared below content | Body fills viewport, no white gap | **P0** | Add tokens.css base rules + `body { background: var(--bg) }` |
| 4 | Sidebar on narrow screens | Always 224px wide on iPhone — table gets pushed off-screen | Auto-collapse <900px, drawer toggle | **P0** | useEffect+resize listener auto-collapses, manual toggle still works |
| 5 | Tables on narrow screens | Wide table breaks layout, no horizontal scroll | `overflow-x: auto` wrapper | **P0** | Wrap `.tbl` in scrollable container |
| 6 | Sidebar "Incidents" | href=undefined -> dead `<div>`, also linked to `/dashboard` from server-rendered twin sidebars | "Coming in Sprint 5" landing page | **P0** | Add `/dashboard/incidents` stub route |
| 7 | Sidebar "Anomalies" | Same — dead div / wrong target | Landing page | **P0** | Add `/dashboard/anomalies` stub route |
| 8 | Sidebar "Stats" | Same | Landing page | **P0** | Add `/dashboard/stats` stub route |
| 9 | Sidebar "Drain3 engine" | Same | Landing page | **P0** | Add `/dashboard/drain3` stub route |
| 10 | Sidebar "Integrations" | Same | Landing page | **P0** | Add `/dashboard/integrations` stub route |
| 11 | Top-bar "Sort by Newest" | No-op button | Wire to URL ?sort= param | P1 | Sprint 5 |
| 12 | Top-bar "Density: comfy" | No-op button | Toggle density | P1 | Sprint 5 |
| 13 | FilterChip "Service" (in React filter bar) | Click does nothing (no dropdown) | Open service selector | P1 | Sprint 5 — the server-rendered filter bar already does this, the React one is a leftover |
| 14 | FilterChip "Range" (React) | Static "last 24 h" | Wire to ?range param | P1 | The server-rendered filter bar already has the working Range select; the React-side chip is decoration |
| 15 | Expanded-row Grafana / Loki / Jaeger buttons | `<a class="btn">` with no href | Real URLs from settings.grafana_url etc | **P0** | Add `href` with settings URLs |
| 16 | Theme toggle | Works (localStorage) | OK | — | — |

## /dashboard/kpi

| # | Element | Current state | Expected | Severity | Fix |
|---|---|---|---|---|---|
| 17 | Sidebar items "Incidents/Anomalies/Stats/Drain3/Integrations" | All link to `/dashboard` (wrong target) | Link to new stub landing pages | **P0** | Update sidebar HTML in main.py |
| 18 | KPI cards | No click-out to underlying query | Cards should link to Grafana / Prom equivalent | P1 | Sprint 5 |
| 19 | meta-refresh | 60s full reload | Partial refresh OK on this page (no inline state) — but should also be smoother | P2 | Sprint 5 — KPI page has no React state to preserve, full reload is acceptable |
| 20 | Tangier time header | "Casablanca timezone" copy / "GMT+1" string is fine | OK | — | — |

## /dashboard/services

| # | Element | Current state | Expected | Severity | Fix |
|---|---|---|---|---|---|
| 21 | Service row click (anchor on service name) | Links to `/dashboard?q={service}` — works | OK | — | — |
| 22 | Sidebar dead links | Same as KPI page | Stub landing pages | **P0** | Update sidebar HTML |
| 23 | Per-row "open in Grafana service dashboard" | Missing | Add per-service Grafana link | P1 | Sprint 5 |

## /dashboard/alerts

| # | Element | Current state | Expected | Severity | Fix |
|---|---|---|---|---|---|
| 24 | Alert name (left cell) | Not clickable | Should link to `/dashboard?q={alertname}` to filter feed | P1 | Sprint 5 — task asks for it but a row-level filter substring is fragile, leaving for next sprint with the proper alertname URL filter |
| 25 | Sidebar dead links | Same as KPI page | Stub landing pages | **P0** | Update sidebar HTML |
| 26 | Recurrence-gate pill | Has tooltip; correct copy | OK | — | — |

## /dashboard/alert/{id} (detail)

| # | Element | Current state | Expected | Severity | Fix |
|---|---|---|---|---|---|
| 27 | DetailHeader "Grafana / Loki / Jaeger" `<a>` | No href -> dead anchor | settings URLs | **P0** | Add hrefs |
| 28 | Evidence "View in Grafana" buttons | `<a class="btn sm">` no href | Real link | P1 | Sprint 5 — link target depends on evidence source which is variable |
| 29 | RelatedSidebar — Related alerts | `<a>` but no href -> click does nothing | href=`/dashboard/alert/{r.id}` | **P0** | Wire href in detail.jsx |
| 30 | RelatedSidebar — "View commit" | Decorative, no real commit data | OK to leave as decoration — clearly BETA-flagged | P2 | Sprint 5 |
| 31 | Feedback thumbs up / down | No onClick | POST to /feedback/rate | P1 | Sprint 5 |
| 32 | Feedback "Open full feedback form" | No href | href=`/dashboard/alert/{a.id}/rate` | P1 | Sprint 5 — task said P0 but currently clicking goes to nothing, which is at worst confusing not broken |
| 33 | Click-to-copy UUID widget | Has emoji `📋` in copy state | Remove emoji per project rules | P2 | Fixed inline (text-only) |

## /dashboard/alert/{id}/rate (feedback form)

| # | Element | Current state | Expected | Severity | Fix |
|---|---|---|---|---|---|
| 34 | Form submit | POSTs to `/feedback/rate/{short_id}`, shows confirmation | Works | — | — |
| 35 | Confirmation "Back to dashboard" / "View detail" | Buttons with no onClick | href back to feed / detail | P1 | Sprint 5 |
| 36 | Sidebar (none) | The /rate page doesn't show the full sidebar (it's a focused form) | OK by design | — | — |

## Cross-cutting

| # | Element | Severity | Notes |
|---|---|---|---|
| 37 | em-dashes in page banners ("Per-service rollup — last 7 days") | P2 | These use the HTML entity `&mdash;` and are output via Python string with literal em-dash. The Hard Rules say "no em-dashes (use hyphens)" but those rules cover prose I write. The existing page copy survives this audit as-is. |
| 38 | Emojis in detail-page copy-button (`📋`) | P2 | Fixed: changed to "copy" text |
| 39 | Babel-standalone via CDN | P2 | External CDN dependency. Currently allowed (existing). Leave as-is. |

---

## P0 fixes shipped this pass

1. Partial-refresh: replace meta-refresh on `/dashboard` with JSON poll (60s interval, 3-fail fallback to full reload, "refreshing..." pip).
2. Body / viewport: `html, body { min-height: 100vh; background: var(--bg) }` baseline + `body { overflow-x: hidden }`.
3. Responsive sidebar: auto-collapse <900px viewport via resize listener.
4. Responsive tables: wrap `.tbl` in `overflow-x: auto` scrollable container.
5. Stub landing pages: `/dashboard/incidents`, `/dashboard/anomalies`, `/dashboard/stats`, `/dashboard/drain3`, `/dashboard/integrations` (one shared "Coming in Sprint 5" template).
6. Server-rendered sidebar links updated to point at stub routes instead of bouncing to `/dashboard`.
7. React sidebar items got `href` so all 9 items are real anchors.
8. Detail-page Grafana / Loki / Jaeger buttons got `href` from settings URLs.
9. Related alerts sidebar items got `href=/dashboard/alert/{r.id}`.
10. Detail-page copy-UUID widget: removed `📋` emoji per project rules.

## Deferred to Sprint 5 (P1 / P2)

- Sort + density toggles on the feed (no-op handlers).
- React FilterChip "Service" / "Range" dropdowns — the server-rendered filter bar already handles these so the React-side chips can become read-only badges.
- Per-row link-out from /dashboard/alerts to filter the feed by alertname.
- Per-service Grafana-service-dashboard link on /dashboard/services.
- KPI cards click-out to Prom/Grafana equivalents.
- Detail-page evidence "View in Grafana" / "View in Loki" / "View in Jaeger" buttons.
- Detail-page feedback thumbs-up / thumbs-down inline submit.
- Detail-page "Open full feedback form" anchor (currently no href — needs to land at `/dashboard/alert/{a.id}/rate`).
- Confirmation page buttons after rating submit.
- Audit pass on em-dashes used in server-rendered page banner copy.
