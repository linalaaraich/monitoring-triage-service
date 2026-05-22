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

function FilterBar({ openFilter, onOpen }) {
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
        <FilterChip label="Environment" value="prod, stg" open={openFilter==='env'} onClick={()=>onOpen(openFilter==='env'?null:'env')}/>
        {openFilter === 'env' && <EnvDropdown/>}
      </div>
      <div style={{ position: "relative" }}>
        <FilterChip label="Namespace" value="all" open={openFilter==='ns'} onClick={()=>onOpen(openFilter==='ns'?null:'ns')}/>
        {openFilter === 'ns' && <NsDropdown/>}
      </div>
      <FilterChip label="Service" value="all"/>
      <div style={{ position: "relative" }}>
        <FilterChip label="Verdict" value="ESCALATE +1" open={openFilter==='verdict'} onClick={()=>onOpen(openFilter==='verdict'?null:'verdict')}/>
        {openFilter === 'verdict' && <VerdictDropdown/>}
      </div>
      <FilterChip label="Range" value="last 24 h"/>

      <div style={{
        marginLeft: 6, display: "flex", alignItems: "center", gap: 8,
        background: "var(--bg-soft)", border: "1px solid var(--border)",
        borderRadius: 7, padding: "6px 10px", flex: 1, maxWidth: 360,
      }}>
        <Icon.search style={{ color: "var(--muted)" }}/>
        <input className="input" style={{ background: "transparent", border: 0, padding: 0, flex: 1, fontSize: 13 }}
          placeholder="Search alert, service, component, RCA text…"/>
        <span className="mono" style={{ fontSize: 10.5, color: "var(--muted-2)" }}>⌘K</span>
      </div>

      <div style={{ flex: 1 }}></div>
      <button className="btn ghost" style={{ color: "var(--muted)", fontSize: 12.5 }}>Clear all</button>
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
function DropdownRow({ checked, color, label, count, mono }) {
  return (
    <div style={{
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
function EnvDropdown() {
  return <DropdownPanel>
    <div style={{ fontSize: 10.5, color: "var(--muted)", textTransform: "uppercase", letterSpacing: 0.08, padding: "4px 8px 8px" }}>Environment</div>
    <DropdownRow checked color="#e06070" label="prod" count="3"/>
    <DropdownRow checked color="#f0a050" label="stg" count="2"/>
    <DropdownRow color="#f0a050" label="preprod" count="1"/>
    <DropdownRow color="#4ea8de" label="uat" count="1"/>
    <DropdownRow color="#4ea8de" label="int" count="0"/>
    <DropdownRow color="#8890a0" label="dev" count="1"/>
  </DropdownPanel>;
}
function NsDropdown() {
  return <DropdownPanel w={240}>
    <div style={{ display: "flex", alignItems: "center", gap: 6, background: "var(--bg-soft)", borderRadius: 6, padding: "5px 9px", marginBottom: 6 }}>
      <Icon.search style={{ color: "var(--muted-2)" }}/>
      <input className="input" placeholder="Filter namespaces…" style={{ background: "transparent", border: 0, padding: 0, flex: 1, fontSize: 12.5 }}/>
    </div>
    <DropdownRow checked label="app" count="2" mono/>
    <DropdownRow label="rental" count="2" mono/>
    <DropdownRow label="network" count="1" mono/>
    <DropdownRow label="observability" count="1" mono/>
    <DropdownRow label="camera" count="1" mono/>
    <DropdownRow label="kube-system" count="0" mono/>
  </DropdownPanel>;
}
function VerdictDropdown() {
  return <DropdownPanel>
    <DropdownRow checked color="#e06070" label="ESCALATE" count="3"/>
    <DropdownRow checked color="#f0a050" label="SHELVED" count="1"/>
    <DropdownRow color="#8890a0" label="DISMISS" count="2"/>
    <DropdownRow color="#4ea8de" label="PENDING" count="1"/>
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
          {a.reason.split(new RegExp(`(${a.boldSubject || '___NONE___'})`)).map((p, i) =>
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
              <button className="btn sm ghost" style={{ color: "var(--muted)" }}>
                <Icon.copy2/> Copy
              </button>
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
        <button className="btn primary lift" style={{ justifyContent: "space-between" }}>
          <span>View full detail</span><Icon.chevR/>
        </button>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
          <a className="btn lift" style={{ justifyContent: "space-between" }}>Grafana <Icon.ext/></a>
          <a className="btn lift" style={{ justifyContent: "space-between" }}>Loki <Icon.ext/></a>
          <a className="btn lift" style={{ justifyContent: "space-between" }}>Jaeger <Icon.ext/></a>
          <a className="btn lift" style={{ justifyContent: "space-between" }}>Rate alert <Icon.ext/></a>
        </div>
        {a.fireCount > 1 && <div style={{
          fontSize: 12, color: "var(--muted)", marginTop: 4,
          display: "flex", alignItems: "center", gap: 6,
        }}>
          <Icon.loop size={12}/> Fired {a.fireCount} times in last 24 h
        </div>}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────
function Pagination({ shown = 20, total = 287, page = 1 }) {
  return (
    <div style={{
      display: "flex", alignItems: "center", justifyContent: "space-between",
      padding: "14px 22px", borderTop: "1px solid var(--border)",
      background: "var(--bg-soft)",
    }}>
      <div style={{ fontSize: 12.5, color: "var(--muted)" }}>
        Showing <span style={{ color: "var(--text)" }}>{(page-1)*20+1}–{Math.min(page*20, total)}</span> of <span style={{ color: "var(--text)" }}>{total}</span> alerts
      </div>
      <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
        <button className="btn sm" style={{ color: "var(--muted)" }}>← Prev</button>
        {[1,2,3].map(n => <button key={n} className="btn sm" style={{
          minWidth: 28, justifyContent: "center",
          background: n === page ? "var(--card-hi)" : "transparent",
          borderColor: n === page ? "var(--border-hi)" : "transparent",
          color: n === page ? "var(--text)" : "var(--muted)",
        }}>{n}</button>)}
        <span style={{ color: "var(--muted-2)", padding: "0 6px" }}>…</span>
        <button className="btn sm" style={{ minWidth: 28, justifyContent: "center", color: "var(--muted)" }}>15</button>
        <button className="btn sm">Next →</button>
      </div>
      <div style={{ fontSize: 12, color: "var(--muted-2)" }}>
        Auto-refresh in <span className="mono" style={{ color: "var(--muted)" }}>00:12</span>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────
function DashboardChrome({ children, state, openFilter, setOpenFilter, active = "triage" }) {
  const [theme] = window.useTheme();
  const [collapsed, setCollapsed] = window.useSidebarCollapsed();
  return (
    <div className="cires" data-theme={theme} style={{ background: "var(--bg)", minHeight: "100%", display: "flex" }}>
      <window.Sidebar active={active} collapsed={collapsed} onToggleCollapse={() => setCollapsed(!collapsed)}/>
      <div style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
        <TopBar uptimeSec={47812} openAlerts={7} emailed24h={12} shelved24h={38} medianLatency={4.3}/>
        <FilterBar openFilter={openFilter} onOpen={setOpenFilter}/>
        <div style={{ padding: "16px 22px 0" }}>
          <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", marginBottom: 10 }}>
            <div>
              <div style={{ fontSize: 12.5, color: "var(--muted)" }}>
                The cheap-path gates absorbed <span style={{ color: "var(--accent-green)" }}>147</span> alerts since midnight. Showing what the LLM judged worth your attention.
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
      </div>
    </div>
  );
}

// Stateful dashboard wrapper — used inside artboards. Mode controls which state to show.
function Dashboard({ mode = "default" }) {
  const [expandedId, setExpandedId] = useDashState(mode === "expanded" ? "8df8a37a" : null);
  const [openFilter, setOpenFilter] = useDashState(mode === "filters" ? "ns" : null);
  const [toast, setToast] = useDashState(null);

  const rows = window.CIRES_ALERTS;

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
              The cheap-path gates absorbed <strong style={{ color: "var(--accent-green)" }}>147</strong> alerts since midnight. Nothing required your attention.
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

  return (
    <DashboardChrome openFilter={openFilter} setOpenFilter={setOpenFilter}>
      <DashboardTable rows={rows} expandedId={expandedId} onToggle={(id) => setExpandedId(expandedId === id ? null : id)}/>
      {toast && <div className="toast">Copied {toast} to clipboard</div>}
    </DashboardChrome>
  );
}

Object.assign(window, { Dashboard });
