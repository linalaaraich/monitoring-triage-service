/* global React, Icon */
// Observability · AI RCA — left navigation sidebar

const SIDEBAR_W = 224;
const SIDEBAR_W_COLLAPSED = 64;

// Fallback badge values — used when window.CIRES_SIDEBAR_BADGES is not
// server-injected (i.e. design canvas viewed directly).
const NAV_BADGE_FALLBACKS = { triage: 7, incidents: 3, anomalies: "12" };

const NAV_GROUPS = [
  {
    label: "Incident response",
    items: [
      { id: "triage",    label: "Triage feed",   icon: "triage",    accent: "var(--accent-red)" },
      { id: "incidents", label: "Incidents",     icon: "incidents", accent: "var(--accent-orange)" },
      { id: "anomalies", label: "Anomalies",     icon: "anomalies" },
    ],
  },
  {
    label: "Insights",
    items: [
      { id: "stats",     label: "Stats",          icon: "stats" },
      { id: "services",  label: "Services",       icon: "services" },
      { id: "kpi",       label: "KPI · Evaluation", icon: "kpi", href: "/dashboard/v2/kpi" },
    ],
  },
  {
    label: "Configuration",
    items: [
      { id: "alerts-cfg", label: "Alerts",         icon: "alerts" },
      { id: "drain3",     label: "Drain3 engine",  icon: "drain3" },
      { id: "integrations", label: "Integrations", icon: "integrations" },
    ],
  },
];

// Inline stroke-only icons (16px), single-color
function NavIcon({ name, size = 16 }) {
  const p = { width: size, height: size, viewBox: "0 0 16 16", fill: "none",
              stroke: "currentColor", strokeWidth: 1.45, strokeLinecap: "round", strokeLinejoin: "round" };
  switch (name) {
    case "triage":     return <svg {...p}><path d="M2 4h12M2 8h12M2 12h7"/><circle cx="13" cy="12" r="1.6" fill="currentColor"/></svg>;
    case "incidents":  return <svg {...p}><path d="M8 1.5 1.7 13h12.6L8 1.5Z"/><path d="M8 6.5v3" /><circle cx="8" cy="11.3" r=".4" fill="currentColor" stroke="none"/></svg>;
    case "anomalies":  return <svg {...p}><path d="M1.5 9.5 4 6l2.5 4L9 4l2.5 6L14 6.5"/><circle cx="4" cy="6" r=".6" fill="currentColor" stroke="none"/><circle cx="9" cy="4" r=".6" fill="currentColor" stroke="none"/></svg>;
    case "stats":      return <svg {...p}><path d="M2 13V4M6 13V7M10 13v-4M14 13V2"/></svg>;
    case "services":   return <svg {...p}><rect x="2" y="2.5" width="5" height="5" rx="1"/><rect x="9" y="2.5" width="5" height="5" rx="1"/><rect x="2" y="8.5" width="5" height="5" rx="1"/><rect x="9" y="8.5" width="5" height="5" rx="1"/></svg>;
    case "kpi":        return <svg {...p}><path d="M2 12V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v8"/><path d="M1.5 13h13"/><path d="m4.5 9 2.5-2.5L9 9l3-3.5"/></svg>;
    case "alerts":     return <svg {...p}><path d="M3.5 11.5h9l-1-1.2V7a3.5 3.5 0 1 0-7 0v3.3l-1 1.2Z"/><path d="M6.5 13a1.5 1.5 0 0 0 3 0"/></svg>;
    case "drain3":     return <svg {...p}><path d="M3 4h10M3 8h10M3 12h6"/><path d="M11 12h3M12.5 10.5v3" stroke="currentColor"/></svg>;
    case "integrations": return <svg {...p}><circle cx="5" cy="5" r="2.5"/><circle cx="11" cy="11" r="2.5"/><path d="M7 7l2 2"/></svg>;
    default: return <svg {...p}><circle cx="8" cy="8" r="5"/></svg>;
  }
}

function NavItem({ item, active, collapsed }) {
  // When the nav item carries an `href`, render an <a> so the operator can
  // click into the linked v2 surface (e.g. KPI · Evaluation → /dashboard/v2/kpi).
  // Items without href keep the existing div-only behaviour — no regression
  // on the triage/incidents/anomalies items that don't have their own routes yet.
  const Wrapper = item.href ? "a" : "div";
  const wrapperProps = item.href
    ? { href: item.href, style: { textDecoration: "none" } }
    : {};
  return (
    <Wrapper {...wrapperProps} title={collapsed ? item.label : undefined} style={{
      ...(item.href ? { textDecoration: "none" } : {}),
      display: "flex", alignItems: "center", gap: 11,
      padding: collapsed ? "9px 0" : "8px 12px",
      justifyContent: collapsed ? "center" : "flex-start",
      borderRadius: 8,
      cursor: "pointer",
      background: active ? "var(--card-hi)" : "transparent",
      border: "1px solid " + (active ? "var(--border-hi)" : "transparent"),
      color: active ? "var(--text)" : "var(--text-soft)",
      position: "relative",
      transition: "background .12s",
    }}>
      {active && <span style={{
        position: "absolute", left: -1, top: 8, bottom: 8, width: 2.5,
        background: "var(--accent-blue)", borderRadius: 3,
      }}/>}
      <span style={{
        display: "inline-flex", color: active ? "var(--accent-blue)" : "var(--muted)",
      }}>
        <NavIcon name={item.icon}/>
      </span>
      {!collapsed && <span style={{ flex: 1, fontSize: 13, fontWeight: active ? 500 : 400 }}>
        {item.label}
      </span>}
      {!collapsed && item.badge != null && (
        <span style={{
          fontSize: 10.5, fontWeight: 600,
          padding: "1px 7px", borderRadius: 999,
          background: item.accent ? `color-mix(in oklab, ${item.accent} 18%, transparent)` : "var(--card)",
          color: item.accent || "var(--muted)",
          border: "1px solid " + (item.accent ? `color-mix(in oklab, ${item.accent} 35%, transparent)` : "var(--border)"),
          fontFamily: "var(--font-mono)", fontFeatureSettings: '"tnum"',
        }}>{item.badge}</span>
      )}
    </Wrapper>
  );
}

function Sidebar({ active = "triage", collapsed = false, onToggleCollapse }) {
  const w = collapsed ? SIDEBAR_W_COLLAPSED : SIDEBAR_W;
  // Resolve badges at render time so server-injected window.CIRES_SIDEBAR_BADGES
  // wins, with NAV_BADGE_FALLBACKS as the safety net.
  const injectedBadges = (typeof window !== "undefined" ? window.CIRES_SIDEBAR_BADGES : null) || {};
  const resolveBadge = (id) => {
    if (injectedBadges[id] != null) return injectedBadges[id];
    if (NAV_BADGE_FALLBACKS[id] != null) return NAV_BADGE_FALLBACKS[id];
    return undefined;
  };
  const navGroups = NAV_GROUPS.map(g => ({
    ...g,
    items: g.items.map(it => {
      const b = resolveBadge(it.id);
      return b !== undefined ? { ...it, badge: b } : it;
    }),
  }));
  return (
    <aside style={{
      width: w, flexShrink: 0,
      background: "var(--bg-soft)",
      borderRight: "1px solid var(--border)",
      display: "flex", flexDirection: "column",
      alignSelf: "stretch",
      transition: "width .15s",
    }}>
      {/* Brand + collapse toggle */}
      <div style={{
        display: "flex", alignItems: "center", gap: 10,
        padding: collapsed ? "14px 0" : "14px 14px 14px 16px",
        justifyContent: collapsed ? "center" : "flex-start",
        borderBottom: "1px solid var(--border)",
        height: 60, flexShrink: 0,
      }}>
        <div style={{
          width: 28, height: 28, borderRadius: 8,
          background: "linear-gradient(135deg, #4ea8de, #b07ee8)",
          display: "grid", placeItems: "center", flexShrink: 0,
        }}>
          <svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="#0f1117" strokeWidth="2" strokeLinecap="round">
            <circle cx="8" cy="8" r="2"/>
            <path d="M3 8a5 5 0 0 1 10 0M1 8a7 7 0 0 1 14 0"/>
          </svg>
        </div>
        {!collapsed && <div style={{ display: "flex", flexDirection: "column", lineHeight: 1.15, flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 13.5, fontWeight: 600, color: "var(--text)" }}>Observability</div>
          <div style={{ fontSize: 11, color: "var(--muted)", letterSpacing: 0.04 }}>AI RCA · v0.1.0</div>
        </div>}
        {!collapsed && (
          <button onClick={onToggleCollapse} title="Collapse sidebar"
            style={{
              width: 26, height: 26, borderRadius: 6,
              background: "transparent", border: "1px solid var(--border)",
              color: "var(--muted)", cursor: "pointer",
              display: "grid", placeItems: "center",
              flexShrink: 0,
            }}>
            <svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M3 3v10M11 5l-3 3 3 3"/>
            </svg>
          </button>
        )}
      </div>

      {/* Nav */}
      <div style={{ flex: 1, overflowY: "auto", padding: collapsed ? "10px 8px" : "12px 12px" }}>
        {navGroups.map((g, gi) => (
          <div key={g.label} style={{ marginBottom: 18 }}>
            {!collapsed && <div style={{
              fontSize: 10, color: "var(--muted-2)",
              textTransform: "uppercase", letterSpacing: 0.12,
              padding: "0 12px 6px", fontWeight: 600,
            }}>{g.label}</div>}
            {collapsed && gi > 0 && <div style={{
              borderTop: "1px solid var(--border)", margin: "0 8px 8px",
            }}/>}
            <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
              {g.items.map(it => (
                <NavItem key={it.id} item={it} active={it.id === active} collapsed={collapsed}/>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Footer */}
      <div style={{
        borderTop: "1px solid var(--border)",
        padding: collapsed ? "10px 8px" : "10px 12px",
        display: "flex", flexDirection: "column", gap: 8,
      }}>
        {collapsed && (
          <button onClick={onToggleCollapse} title="Expand sidebar"
            style={{
              display: "flex", alignItems: "center", justifyContent: "center",
              background: "var(--card)", border: "1px solid var(--border)", padding: "7px 0",
              color: "var(--text-soft)", cursor: "pointer", fontFamily: "inherit",
              fontSize: 12, borderRadius: 7,
            }}>
            <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M3 3v10M6 5l3 3-3 3"/>
            </svg>
          </button>
        )}
        <div style={{
          display: "flex", alignItems: "center", gap: 9,
          padding: collapsed ? "4px 0" : "4px 8px",
          justifyContent: collapsed ? "center" : "flex-start",
        }}>
          <div style={{
            width: 28, height: 28, borderRadius: "50%",
            background: "linear-gradient(135deg, #b07ee8, #40d0d0)",
            display: "grid", placeItems: "center", flexShrink: 0,
            fontSize: 11, fontWeight: 600, color: "#0f1117",
          }}>YB</div>
          {!collapsed && <div style={{ display: "flex", flexDirection: "column", lineHeight: 1.15, flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 12.5, color: "var(--text)" }}>y.benhaddou</div>
            <div style={{ fontSize: 10.5, color: "var(--muted)" }}>on-call · Tier 2</div>
          </div>}
        </div>
      </div>
    </aside>
  );
}

Object.assign(window, { Sidebar, SIDEBAR_W, SIDEBAR_W_COLLAPSED });
