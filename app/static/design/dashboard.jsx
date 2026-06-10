/* global React, EnvPill, VerdictPill, SeverityPill, NsPill, CompPill, ServiceIcon, StateIcon, Icon, TopBar */
// CIRES — Operator Dashboard

const { useState: useDashState } = React;

function FilterChip({ label, value, open, onClick }) {
  return (
    <button className="btn" onClick={onClick} style={{
      gap: 8, fontSize: 12.5, padding: "6px 11px",
      borderColor: open ? "var(--border-hi)" : "var(--border)",
      background: open ? "var(--card-hi)" : "var(--card)",
    }}>
      <span style={{ color: "var(--muted)" }}>{label}</span>
      <span style={{ color: "var(--text)" }}>{value}</span>
      <Icon.chevD style={{ color: "var(--muted)" }}/>
    </button>
  );
}

function chipLabel(set) {
  if (!set || set.size === 0) return "all";
  const arr = Array.from(set);
  if (arr.length === 1) return arr[0];
  return arr[0] + " +" + (arr.length - 1);
}

// Human label for the Range chip from the seeded CIRES_FILTERS.range token.
const _RANGE_LABEL = { "1h": "last 1 h", "6h": "last 6 h", "24h": "last 24 h", "7d": "last 7 d", "15d": "last 15 d" };
function FilterBar({ openFilter, onOpen, searchQuery, setSearchQuery, onSearchSubmit, filters, toggleFilter, clearAllFilters }) {
  const cf = (typeof window !== "undefined" ? window.CIRES_FILTERS : null) || {};
  const rangeLabel = _RANGE_LABEL[cf.range] || (cf.range ? String(cf.range) : "last 15 d");
  return (
    <div style={{
      background: "var(--bg)",
      borderBottom: "1px solid var(--border)",
      padding: "12px 22px",
      display: "flex", alignItems: "center", gap: 10,
      position: "sticky", top: 60, zIndex: 9,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--muted)" }}>
        <Icon.filter/>
        <span style={{ fontSize: 12, textTransform: "uppercase", letterSpacing: 0.08 }}>Filters</span>
      </div>
      <div style={{ position: "relative" }}>
        <FilterChip label="Environment" value={chipLabel(filters.env)} open={openFilter==='env'} onClick={()=>onOpen(openFilter==='env'?null:'env')}/>
        {openFilter === 'env' && <EnvDropdown selected={filters.env} onToggle={(v)=>toggleFilter('env', v)}/>}
      </div>
      <div style={{ position: "relative" }}>
        <FilterChip label="Verdict" value={chipLabel(filters.verdict)} open={openFilter==='verdict'} onClick={()=>onOpen(openFilter==='verdict'?null:'verdict')}/>
        {openFilter === 'verdict' && <VerdictDropdown selected={filters.verdict} onToggle={(v)=>toggleFilter('verdict', v)}/>}
      </div>
      <div style={{ position: "relative" }}>
        <FilterChip label="Severity" value={chipLabel(filters.severity)} open={openFilter==='severity'} onClick={()=>onOpen(openFilter==='severity'?null:'severity')}/>
        {openFilter === 'severity' && <SeverityDropdown selected={filters.severity} onToggle={(v)=>toggleFilter('severity', v)}/>}
      </div>
      <div style={{ position: "relative" }}>
        <FilterChip label="Family" value={chipLabel(filters.family)} open={openFilter==='family'} onClick={()=>onOpen(openFilter==='family'?null:'family')}/>
        {openFilter === 'family' && <FamilyDropdown selected={filters.family} onToggle={(v)=>toggleFilter('family', v)}/>}
      </div>
      {/* Range reflects the active server window (CIRES_FILTERS.range); not yet
          operator-editable in-place — change via ?range= deep-link. */}
      <FilterChip label="Range" value={rangeLabel}/>

      <div style={{
        marginLeft: 6, display: "flex", alignItems: "center", gap: 8,
        background: "var(--bg-soft)", border: "1px solid var(--border)",
        borderRadius: 7, padding: "6px 10px", flex: 1, maxWidth: 360,
      }}>
        <Icon.search style={{ color: "var(--muted)" }}/>
        <input className="input" style={{ background: "transparent", border: 0, padding: 0, flex: 1, fontSize: 13 }}
          placeholder="Search alert, service, component, RCA text… (Enter)"
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          onKeyDown={e => { if (e.key === "Enter") onSearchSubmit(searchQuery); }}/>
        <span className="mono" style={{ fontSize: 10.5, color: "var(--muted-2)" }}>⏎</span>
      </div>

      <div style={{ flex: 1 }}></div>
      <button className="btn ghost" style={{ color: "var(--muted)", fontSize: 12.5 }} onClick={clearAllFilters}>Clear all</button>
    </div>
  );
}

function DropdownPanel({ children, w = 220, style }) {
  return (
    <div style={{
      position: "absolute", top: "calc(100% + 6px)", left: 0,
      background: "var(--card)", border: "1px solid var(--border-hi)",
      borderRadius: 10, padding: 8, width: w, zIndex: 20,
      boxShadow: "0 18px 38px rgba(0,0,0,.5)",
      ...style,
    }}>
      {children}
    </div>
  );
}
function DropdownRow({ checked, color, label, count, mono, onClick }) {
  return (
    <div onClick={onClick} style={{
      display: "flex", alignItems: "center", gap: 9,
      padding: "6px 8px", borderRadius: 6,
      background: checked ? "var(--card-alt)" : "transparent",
      cursor: "pointer", fontSize: 13,
    }}>
      <span style={{
        width: 14, height: 14, borderRadius: 4,
        border: "1px solid " + (checked ? color || "var(--accent-blue)" : "var(--border-hi)"),
        background: checked ? (color || "var(--accent-blue)") : "transparent",
        display: "grid", placeItems: "center", color: "#0f1117",
      }}>{checked && <Icon.check style={{ width: 10, height: 10 }}/>}</span>
      {color && !checked && <span style={{ width: 8, height: 8, borderRadius: "50%", background: color }}></span>}
      <span className={mono ? "mono" : ""} style={{ flex: 1, color: "var(--text)", fontSize: mono ? 12.5 : 13 }}>{label}</span>
      <span style={{ fontSize: 11, color: "var(--muted)" }}>{count}</span>
    </div>
  );
}
function EnvDropdown({ selected, onToggle }) {
  const sel = selected || new Set();
  const opts = [
    { color: "#e06070", label: "prod", count: "3" },
    { color: "#f0a050", label: "stg", count: "2" },
    { color: "#f0a050", label: "preprod", count: "1" },
    { color: "#4ea8de", label: "uat", count: "1" },
    { color: "#4ea8de", label: "int", count: "0" },
    { color: "#8890a0", label: "dev", count: "1" },
  ];
  return <DropdownPanel>
    <div style={{ fontSize: 10.5, color: "var(--muted)", textTransform: "uppercase", letterSpacing: 0.08, padding: "4px 8px 8px" }}>Environment</div>
    {opts.map(o => (
      <DropdownRow key={o.label} checked={sel.has(o.label)} color={o.color} label={o.label} count={o.count}
        onClick={onToggle ? () => onToggle(o.label) : undefined}/>
    ))}
  </DropdownPanel>;
}
function VerdictDropdown({ selected, onToggle }) {
  // Values are the lowercase server filter tokens (?verdict=…); _V2_FILTER_VERDICTS.
  const sel = selected || new Set();
  const opts = [
    { color: "#e06070", label: "escalate" },
    { color: "#f0a050", label: "shelve" },
    { color: "#8890a0", label: "dismiss" },
    { color: "#4ea8de", label: "investigate" },
  ];
  return <DropdownPanel>
    {opts.map(o => (
      <DropdownRow key={o.label} checked={sel.has(o.label)} color={o.color} label={o.label}
        onClick={onToggle ? () => onToggle(o.label) : undefined}/>
    ))}
  </DropdownPanel>;
}
function SeverityDropdown({ selected, onToggle }) {
  // Values are the lowercase server filter tokens (?severity=…).
  const sel = selected || new Set();
  const opts = [
    { color: "#e06070", label: "critical" },
    { color: "#f0a050", label: "warning" },
    { color: "#4ea8de", label: "info" },
    { color: "#8890a0", label: "none" },
  ];
  return <DropdownPanel>
    {opts.map(o => (
      <DropdownRow key={o.label} checked={sel.has(o.label)} color={o.color} label={o.label}
        onClick={onToggle ? () => onToggle(o.label) : undefined}/>
    ))}
  </DropdownPanel>;
}
function FamilyDropdown({ selected, onToggle }) {
  // Values are the lowercase server family tokens (?family=…); _V2_FILTER_FAMILIES.
  const sel = selected || new Set();
  const opts = ["cpu", "memory", "latency", "disk", "network", "pod", "drain", "kong", "spring"];
  return <DropdownPanel w={200}>
    <div style={{ fontSize: 10.5, color: "var(--muted)", textTransform: "uppercase", letterSpacing: 0.08, padding: "4px 8px 8px" }}>Alert family</div>
    {opts.map(o => (
      <DropdownRow key={o} checked={sel.has(o)} label={o} mono
        onClick={onToggle ? () => onToggle(o) : undefined}/>
    ))}
  </DropdownPanel>;
}

// ─────────────────────────────────────────────────────────
// Row
function AlertRow({ a, expanded, onToggle, onCopy }) {
  const verdictMap = window.VERDICT_DOT;
  return (
    <React.Fragment>
      <tr className={"row" + (expanded ? " expanded" : "")} onClick={onToggle}>
        <td style={{ width: 28, paddingRight: 0, color: "var(--muted)" }}>
          <span style={{ display: "inline-flex", transform: expanded ? "rotate(90deg)" : "none", transition: "transform .12s" }}>
            <Icon.chevR/>
          </span>
        </td>
        <td style={{ width: 28, paddingLeft: 0, paddingRight: 0 }}>
          <StateIcon kind={a.indicator}/>
        </td>
        <td style={{ color: "var(--text-soft)", whiteSpace: "nowrap", paddingRight: 14 }}>
          <div className="mono" style={{ fontSize: 12.5, color: "var(--text)", fontFeatureSettings: '"tnum"' }}>
            {a.timeShort || (a.timeLocal && a.timeLocal.slice(11, 19)) || "—"}
          </div>
          <div className="mono" style={{ fontSize: 10.5, color: "var(--muted-2)", marginTop: 1, fontFeatureSettings: '"tnum"' }}>
            {a.dateShort || (a.timeLocal && a.timeLocal.slice(0, 10)) || a.relTime}
          </div>
        </td>
        <td><EnvPill env={a.env}/></td>
        <td><NsPill ns={a.namespace}/></td>
        <td>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 7, color: "var(--text-soft)" }}>
            <span style={{ color: "var(--muted)", display: "inline-flex" }}><ServiceIcon type={a.serviceType}/></span>
            <span style={{ fontSize: 12.5 }}>{a.serviceType}</span>
          </span>
        </td>
        <td><CompPill c={a.component}/></td>
        <td style={{ color: "var(--text)", fontSize: 13.5, fontWeight: 500, maxWidth: 320 }}>{a.alertPlain}</td>
        <td><VerdictPill v={a.verdict}/></td>
        <td><SeverityPill s={a.severity}/></td>
        <td style={{ width: 110 }}>
          <button className="mono" onClick={(e)=>{ e.stopPropagation(); onCopy && onCopy(a.id); }}
            style={{
              background: "transparent", border: "1px solid var(--border)",
              padding: "3px 8px", borderRadius: 5, fontSize: 11.5,
              color: "var(--muted)", cursor: "pointer",
              display: "inline-flex", alignItems: "center", gap: 6,
            }}>
            {a.id}
            <Icon.copy style={{ opacity: .65 }}/>
          </button>
        </td>
      </tr>
      {expanded && <tr className="expanded-detail">
        <td colSpan={11}>
          <ExpandedDetail a={a}/>
        </td>
      </tr>}
    </React.Fragment>
  );
}

function ExpandedDetail({ a }) {
  return (
    <div style={{
      padding: "18px 22px 20px 56px",
      borderLeft: "3px solid " + (window.VERDICT_DOT[a.verdict] || "var(--border-hi)"),
      display: "grid", gridTemplateColumns: "1.4fr 1fr", gap: 24,
    }}>
      <div>
        <div className="section-label">Reason</div>
        <div style={{ fontSize: 14.5, color: "var(--text)", lineHeight: 1.5, maxWidth: 640 }}>
          {/* Guard against null/missing reason (C4): expanding such a row would
              otherwise throw inside renderToString and blank the whole feed. */}
          {(a.reason || "").split(new RegExp(`(${a.boldSubject || '___NONE___'})`)).map((p, i) =>
            p === a.boldSubject
              ? <strong key={i} className="mono" style={{ color: "var(--accent-yellow)", fontWeight: 600 }}>{p}</strong>
              : <React.Fragment key={i}>{p}</React.Fragment>
          )}
        </div>

        <div style={{ marginTop: 16 }}>
          <div className="section-label">Suggested action</div>
          {a.actions && a.actions[0] && a.actions[0].cmd && a.actions[0].cmd !== "—" ? (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}>
              <span className="codechip">
                <span className="cmd-prefix">$</span>
                {a.actions[0].cmd}
              </span>
              <CopyBtn text={a.actions[0].cmd} className="btn sm ghost"/>
            </div>
          ) : (
            <div style={{ fontSize: 13, color: "var(--muted)" }}>No safe action — see detail page.</div>
          )}
        </div>

        <div style={{ marginTop: 16, display: "flex", flexWrap: "wrap", gap: 6 }}>
          {(a.tags || []).slice(0, 3).map(t => (
            <span key={t} className="pill pill-gray" style={{ fontSize: 10.5, padding: "2px 8px" }}>{t}</span>
          ))}
        </div>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        <div className="section-label">Quick actions</div>
        <a className="btn primary lift" href={`/dashboard/alert/${a.id}`} style={{ justifyContent: "space-between", textDecoration: "none" }}>
          <span>View full detail</span><Icon.chevR/>
        </a>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
          <a className="btn lift" href={safeHref(a.links && a.links.grafana)} target="_blank" rel="noopener noreferrer" style={{ justifyContent: "space-between", textDecoration: "none" }}>Grafana <Icon.ext/></a>
          <a className="btn lift" href={safeHref(a.links && a.links.loki)} target="_blank" rel="noopener noreferrer" style={{ justifyContent: "space-between", textDecoration: "none" }}>Loki <Icon.ext/></a>
          <a className="btn lift" href={safeHref(a.links && a.links.jaeger)} target="_blank" rel="noopener noreferrer" style={{ justifyContent: "space-between", textDecoration: "none" }}>Jaeger <Icon.ext/></a>
          <a className="btn lift" href={`/dashboard/alert/${a.id}/rate`} style={{ justifyContent: "space-between", textDecoration: "none" }}>Rate alert <Icon.ext/></a>
        </div>
        {a.fireCount > 1 && <div style={{
          fontSize: 12, color: "var(--muted)", marginTop: 4,
          display: "flex", alignItems: "center", gap: 6,
        }}>
          {/* No time-window claim: fireCount is the incident's all-time count
              (F-2), not a 24 h figure — the old hardcoded 24 h copy was wrong
              for the default 15 d feed window. */}
          <Icon.loop size={12}/> Fired {a.fireCount} times
        </div>}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────
function Pagination(props) {
  // Real values come from window.CIRES_PAGINATION (server-injected). Falls
  // back to mock numbers if the page is viewed without a backend.
  const p = (typeof window !== "undefined" ? window.CIRES_PAGINATION : null) || {};
  const _total = props.total ?? p.total ?? 0;
  const _page = props.page ?? p.page ?? 1;
  const _size = props.size ?? p.size ?? 20;
  const lastPage = Math.max(1, Math.ceil(_total / _size));
  const startRow = _total === 0 ? 0 : (_page - 1) * _size + 1;
  const endRow = Math.min(_page * _size, _total);

  function navTo(n) {
    if (n < 1 || n > lastPage || n === _page) return;
    const u = new URL(window.location.href);
    u.searchParams.set("page", String(n));
    u.searchParams.set("size", String(_size));
    window.location.href = u.toString();
  }
  // Page numbers: 1, current-1, current, current+1, last. Dedupe + sort.
  const seen = new Set();
  const pageNums = [];
  for (const n of [1, _page - 1, _page, _page + 1, lastPage]) {
    if (n >= 1 && n <= lastPage && !seen.has(n)) { seen.add(n); pageNums.push(n); }
  }
  pageNums.sort((a, b) => a - b);

  return (
    <div style={{
      display: "flex", alignItems: "center", justifyContent: "space-between",
      padding: "14px 22px", borderTop: "1px solid var(--border)",
      background: "var(--bg-soft)",
    }}>
      <div style={{ fontSize: 12.5, color: "var(--muted)" }}>
        Showing <span style={{ color: "var(--text)" }}>{startRow}–{endRow}</span> of <span style={{ color: "var(--text)" }}>{_total}</span> alerts
      </div>
      <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
        <button className="btn sm" onClick={() => navTo(_page - 1)} disabled={_page <= 1}
          style={{ color: _page > 1 ? "var(--text)" : "var(--muted-2)", cursor: _page > 1 ? "pointer" : "default" }}>← Prev</button>
        {pageNums.map((n, i) => {
          const prev = pageNums[i - 1];
          const gap = prev !== undefined && n - prev > 1;
          return (
            <React.Fragment key={n}>
              {gap && <span style={{ color: "var(--muted-2)", padding: "0 6px" }}>…</span>}
              <button className="btn sm" onClick={() => navTo(n)} style={{
                minWidth: 28, justifyContent: "center",
                background: n === _page ? "var(--card-hi)" : "transparent",
                borderColor: n === _page ? "var(--border-hi)" : "transparent",
                color: n === _page ? "var(--text)" : "var(--muted)",
                cursor: "pointer",
              }}>{n}</button>
            </React.Fragment>
          );
        })}
        <button className="btn sm" onClick={() => navTo(_page + 1)} disabled={_page >= lastPage}
          style={{ color: _page < lastPage ? "var(--text)" : "var(--muted-2)", cursor: _page < lastPage ? "pointer" : "default" }}>Next →</button>
      </div>
      <div style={{ fontSize: 12, color: "var(--muted-2)" }}>
        Page <span className="mono" style={{ color: "var(--muted)" }}>{_page} / {lastPage}</span>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────
function DashboardChrome({ children, state, openFilter, setOpenFilter, active = "triage",
  searchQuery = "", setSearchQuery = () => {}, onSearchSubmit = () => {},
  filters = { env: new Set(), verdict: new Set(), severity: new Set(), family: new Set() },
  toggleFilter = () => {}, clearAllFilters = () => {} }) {
  const [theme] = window.useTheme();
  const [collapsed, setCollapsed] = window.useSidebarCollapsed();
  // Cheap-path-since-midnight counter is server-injected via
  // window.CIRES_DASHBOARD_STATS.cheap_path_since_midnight; fall back to the
  // original mock value so the design canvas still renders standalone.
  const _stats = (typeof window !== "undefined" ? window.CIRES_DASHBOARD_STATS : null) || {};
  const cheapPath = _stats.cheap_path_since_midnight ?? 147;
  return (
    <div className="cires" data-theme={theme} style={{ background: "var(--bg)", minHeight: "100%", display: "flex" }}>
      <window.Sidebar active={active} collapsed={collapsed} onToggleCollapse={() => setCollapsed(!collapsed)}/>
      <div style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
        <TopBar/>
        <FilterBar openFilter={openFilter} onOpen={setOpenFilter}
          searchQuery={searchQuery} setSearchQuery={setSearchQuery} onSearchSubmit={onSearchSubmit}
          filters={filters} toggleFilter={toggleFilter} clearAllFilters={clearAllFilters}/>
        <div style={{ padding: "16px 22px 0" }}>
          <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", marginBottom: 10 }}>
            <div>
              <div style={{ fontSize: 12.5, color: "var(--muted)" }}>
                The cheap-path gates absorbed <span style={{ color: "var(--accent-green)" }}>{cheapPath}</span> alerts since midnight. Showing what the LLM judged worth your attention.
              </div>
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <span style={{ fontSize: 12, color: "var(--muted)" }}>Sort by</span>
              <button className="btn sm" style={{ color: "var(--text)" }}>Newest <Icon.chevD/></button>
              <button className="btn sm" style={{ color: "var(--muted)" }}>Density: comfy</button>
            </div>
          </div>
        </div>
        {children}
      </div>
    </div>
  );
}

function DashboardTable({ rows, expandedId, onToggle }) {
  return (
    <div style={{ padding: "10px 22px 0" }}>
      <div className="card" style={{ overflow: "hidden", borderRadius: 12 }}>
        <table className="tbl">
          <thead>
            <tr>
              <th style={{ width: 28 }}></th>
              <th style={{ width: 28 }}></th>
              <th>Time</th>
              <th>Environment</th>
              <th>Namespace</th>
              <th>Service-type</th>
              <th>Component</th>
              <th>Alert</th>
              <th>Verdict</th>
              <th>Severity</th>
              <th>ID</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(a => (
              <AlertRow key={a.id} a={a} expanded={a.id === expandedId} onToggle={() => onToggle(a.id)}/>
            ))}
          </tbody>
        </table>
        {/* Pagination — wired to window.CIRES_PAGINATION (server-injected). */}
        <Pagination/>
      </div>
    </div>
  );
}

// Stateful dashboard wrapper — used inside artboards. Mode controls which state to show.
// FE-H1 (2026-06-04) — the server (/dashboard?verdict=&severity=&family=&env=
// &range=&q=) is the single source of truth for which rows arrive. The React
// FilterBar SEEDS its chip state from window.CIRES_FILTERS (so a deep-link /
// bookmark / partial-refresh stays coherent with the chips) and DRIVES the
// server filters by round-tripping every change through the URL — same pattern
// as Pagination's navTo. There is no second, client-only narrowing of the
// already-server-filtered page.
//
// The chips that map 1:1 to a server filter param are env / verdict / severity
// / family / range / q. (namespace + service_type have no server-side filter,
// so they are not surfaced as live chips — keeping the UI honest.)
function _seedFilterSet(scalar) {
  return scalar ? new Set([String(scalar).toLowerCase()]) : new Set();
}
function _seedFiltersFromCIRES() {
  const cf = (typeof window !== "undefined" ? window.CIRES_FILTERS : null) || {};
  return {
    env: _seedFilterSet(cf.env),
    verdict: _seedFilterSet(cf.verdict),
    severity: _seedFilterSet(cf.severity),
    family: _seedFilterSet(cf.family),
  };
}
// Map a React chip key → its /dashboard URL query param.
const _FILTER_PARAM = { env: "env", verdict: "verdict", severity: "severity", family: "family" };
// Apply a {param: value|null} patch to the current URL and navigate. Clearing
// a value (null/"") removes the param; any change resets pagination to page 1.
function _navWithFilterPatch(patch) {
  if (typeof window === "undefined" || !window.location) return;
  const u = new URL(window.location.href);
  Object.keys(patch).forEach((k) => {
    const v = patch[k];
    if (v === null || v === undefined || v === "") u.searchParams.delete(k);
    else u.searchParams.set(k, String(v));
  });
  u.searchParams.delete("page");
  window.location.href = u.toString();
}

function Dashboard({ mode = "default" }) {
  const [expandedId, setExpandedId] = useDashState(mode === "expanded" ? "8df8a37a" : null);
  // F-5 (2026-06-10): the "filters" canvas mode used to open the mock
  // namespace dropdown ("ns"); that orphaned component is removed — open the
  // real EnvDropdown instead so the artboard still shows an open panel.
  const [openFilter, setOpenFilter] = useDashState(mode === "filters" ? "env" : null);
  const [toast, setToast] = useDashState(null);
  // Seed the search box + chips from the server-resolved filter set so the UI
  // reflects the active URL (?q=…&verdict=… etc.), not a fresh empty state.
  const _cf = (typeof window !== "undefined" ? window.CIRES_FILTERS : null) || {};
  const [searchQuery, setSearchQuery] = useDashState(_cf.q || "");
  const [filters, setFilters] = useDashState(_seedFiltersFromCIRES());
  // 2026-06-02 — alerts as state so partial-refresh swaps the rows
  // without remounting Dashboard (which would lose expandedId / filters).
  // Seeded from the server-injected window.CIRES_ALERTS, then updated by
  // the cires:refreshed event listener wired below.
  const [rows, setRows] = useDashState(window.CIRES_ALERTS || []);
  React.useEffect(() => {
    const onRefresh = (e) => {
      const next = (e && e.detail && e.detail.alerts) || window.CIRES_ALERTS || [];
      setRows(next);
    };
    window.addEventListener("cires:refreshed", onRefresh);
    return () => window.removeEventListener("cires:refreshed", onRefresh);
  }, []);

  // FE-H1: a chip toggle round-trips through the URL (server re-filters the
  // whole dataset, not just the loaded page) instead of a client-only Set
  // mutation. Single-select per dimension to match the server param. Clicking
  // the already-active value clears that filter.
  function toggleFilter(key, value) {
    const param = _FILTER_PARAM[key];
    if (!param) return; // non-URL-backed dimension — no-op (not surfaced)
    const cur = filters[key] && filters[key].size ? Array.from(filters[key])[0] : null;
    const nextVal = (cur === String(value).toLowerCase()) ? null : String(value).toLowerCase();
    _navWithFilterPatch({ [param]: nextVal });
  }
  function setSearchAndNav(value) {
    _navWithFilterPatch({ q: (value || "").trim() || null });
  }
  function clearAllFilters() {
    _navWithFilterPatch({ env: null, verdict: null, severity: null, family: null, q: null, range: null });
  }

  if (mode === "empty") {
    return (
      <DashboardChrome openFilter={null} setOpenFilter={()=>{}}>
        <div style={{ padding: "20px 22px 40px" }}>
          <div className="card" style={{ padding: "70px 30px", textAlign: "center" }}>
            <div style={{
              width: 64, height: 64, borderRadius: "50%",
              background: "rgba(107,207,127,.12)",
              border: "1px solid rgba(107,207,127,.4)",
              display: "grid", placeItems: "center", margin: "0 auto 18px",
              color: "var(--accent-green)",
            }}>
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m5 12 5 5L20 7"/></svg>
            </div>
            <div style={{ fontSize: 22, fontWeight: 600, marginBottom: 8 }}>All clear</div>
            <div style={{ color: "var(--muted)", fontSize: 14, maxWidth: 540, margin: "0 auto", lineHeight: 1.55 }}>
              No alerts in the last <strong style={{ color: "var(--text-soft)" }}>24 hours</strong>.<br/>
              The cheap-path gates absorbed <strong style={{ color: "var(--accent-green)" }}>{((typeof window !== "undefined" ? window.CIRES_DASHBOARD_STATS : null) || {}).cheap_path_since_midnight ?? 147}</strong> alerts since midnight. Nothing required your attention.
            </div>
            <div style={{ display: "flex", gap: 10, justifyContent: "center", marginTop: 24 }}>
              <button className="btn">View gate stats</button>
              <button className="btn ghost" style={{ color: "var(--muted)" }}>Change time range</button>
            </div>
          </div>
        </div>
      </DashboardChrome>
    );
  }

  if (mode === "empty-filtered") {
    return (
      <DashboardChrome openFilter={null} setOpenFilter={()=>{}}>
        <div style={{ padding: "20px 22px 40px" }}>
          <div className="card" style={{ padding: "60px 30px", textAlign: "center" }}>
            <div style={{ fontSize: 18, fontWeight: 500, marginBottom: 6 }}>No alerts match your filters</div>
            <div style={{ color: "var(--muted)", fontSize: 13.5, marginBottom: 18 }}>
              You're filtering for <span className="pill pill-red" style={{ marginInline: 4 }}>prod</span> + verdict <span className="pill pill-red" style={{ marginInline: 4 }}>ESCALATE</span> in the last 1 h.
            </div>
            <button className="btn primary">Clear all filters</button>
          </div>
        </div>
      </DashboardChrome>
    );
  }

  if (mode === "pagination") {
    return (
      <DashboardChrome openFilter={null} setOpenFilter={()=>{}}>
        <div style={{ padding: "10px 22px 0" }}>
          <div className="card" style={{ overflow: "hidden", borderRadius: 12 }}>
            <table className="tbl">
              <thead>
                <tr>
                  <th style={{ width: 28 }}></th>
                  <th style={{ width: 28 }}></th>
                  <th>Time</th>
                  <th>Environment</th>
                  <th>Namespace</th>
                  <th>Service-type</th>
                  <th>Component</th>
                  <th>Alert</th>
                  <th>Verdict</th>
                  <th>Severity</th>
                  <th>ID</th>
                </tr>
              </thead>
              <tbody>
                {rows.slice(4, 8).map(a => (
                  <AlertRow key={a.id} a={a} expanded={false} onToggle={()=>{}}/>
                ))}
              </tbody>
            </table>
            <Pagination shown={20} total={287} page={3}/>
          </div>
        </div>
      </DashboardChrome>
    );
  }

  // FE-H1: rows already arrive server-filtered (verdict/severity/family/env/
  // range/q applied in SQL across the FULL dataset, not just this page), so we
  // render them directly — no second client-side narrowing that would only see
  // the loaded page.
  const visibleRows = rows || [];

  return (
    <DashboardChrome openFilter={openFilter} setOpenFilter={setOpenFilter}
      searchQuery={searchQuery} setSearchQuery={setSearchQuery} onSearchSubmit={setSearchAndNav}
      filters={filters} toggleFilter={toggleFilter} clearAllFilters={clearAllFilters}>
      <DashboardTable rows={visibleRows} expandedId={expandedId} onToggle={(id) => setExpandedId(expandedId === id ? null : id)}/>
      {toast && <div className="toast">Copied {toast} to clipboard</div>}
    </DashboardChrome>
  );
}

Object.assign(window, { Dashboard });
