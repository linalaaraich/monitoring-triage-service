/* global React */
// Observability · AI RCA — shared atoms: pills, icons, helpers

const { useState, useEffect } = React;

// ────────────────────────────────────────────────────────────
// Theme — dark | light. Persists in localStorage; broadcast across artboards via storage event.
const THEME_KEY = "obs-rca-theme";
function getInitialTheme() {
  try { return localStorage.getItem(THEME_KEY) || "dark"; } catch (e) { return "dark"; }
}
function useTheme() {
  const [theme, setTheme] = useState(getInitialTheme());
  useEffect(() => {
    const onStorage = (e) => { if (e.key === THEME_KEY && e.newValue) setTheme(e.newValue); };
    window.addEventListener("storage", onStorage);
    // also poll once per second so artboards inside same window (no storage event for self) stay in sync
    const t = setInterval(() => {
      const v = getInitialTheme();
      if (v !== theme) setTheme(v);
    }, 500);
    return () => { window.removeEventListener("storage", onStorage); clearInterval(t); };
  }, [theme]);
  const apply = (next) => {
    try { localStorage.setItem(THEME_KEY, next); } catch (e) {}
    setTheme(next);
  };
  return [theme, apply];
}

function ThemeToggle() {
  const [theme, setTheme] = useTheme();
  const isLight = theme === "light";
  return (
    <button
      onClick={() => setTheme(isLight ? "dark" : "light")}
      title={isLight ? "Switch to dark mode" : "Switch to light mode"}
      style={{
        display: "inline-flex", alignItems: "center", gap: 6,
        background: "var(--card)", border: "1px solid var(--border)",
        color: "var(--text-soft)", padding: "6px 10px", borderRadius: 7,
        cursor: "pointer", fontFamily: "inherit", fontSize: 12,
      }}
    >
      {isLight
        ? <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"><path d="M13.5 9.5A5.5 5.5 0 0 1 6.5 2.5a6 6 0 1 0 7 7Z"/></svg>
        : <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"><circle cx="8" cy="8" r="3"/><path d="M8 1v2M8 13v2M1 8h2M13 8h2M3 3l1.4 1.4M11.6 11.6 13 13M3 13l1.4-1.4M11.6 4.4 13 3"/></svg>
      }
      <span>{isLight ? "Dark" : "Light"}</span>
    </button>
  );
}

// ────────────────────────────────────────────────────────────
// Environment pill colors
const ENV_STYLES = {
  prod:    "pill-red",
  preprod: "pill-amber",
  stg:     "pill-amber",
  uat:     "pill-blue",
  int:     "pill-blue",
  dev:     "pill-gray",
};

const VERDICT_STYLES = {
  ESCALATE: "pill-red",
  DISMISS:  "pill-gray",
  SHELVED:  "pill-amber",
  PENDING:  "pill-blue",
};

const SEVERITY_STYLES = {
  critical: "pill-red",
  warning:  "pill-amber",
  info:     "pill-blue",
};

const VERDICT_DOT = {
  ESCALATE: "#e06070",
  DISMISS:  "#8890a0",
  SHELVED:  "#f0a050",
  PENDING:  "#4ea8de",
};

function EnvPill({ env }) {
  return <span className={`pill ${ENV_STYLES[env] || "pill-gray"}`}>{env}</span>;
}
function VerdictPill({ v, size }) {
  return <span className={`pill ${size==='lg'?'lg':''} ${VERDICT_STYLES[v] || "pill-gray"}`}>
    <span className="dot" style={{ background: VERDICT_DOT[v] }}></span>{v}
  </span>;
}
function SeverityPill({ s, size }) {
  return <span className={`pill ${size==='lg'?'lg':''} ${SEVERITY_STYLES[s] || "pill-gray"}`}>{s}</span>;
}
function NsPill({ ns }) {
  return <span className="pill pill-gray pill-mono">{ns}</span>;
}
function CompPill({ c }) {
  return <span className="pill pill-gray pill-mono">{c}</span>;
}

// ────────────────────────────────────────────────────────────
// Service-type icons. Stroke-only, 16px.
function ServiceIcon({ type, size = 14 }) {
  const s = size;
  const sp = { width: s, height: s, viewBox: "0 0 16 16", fill: "none", stroke: "currentColor", strokeWidth: 1.4, strokeLinecap: "round", strokeLinejoin: "round" };
  switch (type) {
    case "backend":   return <svg {...sp}><rect x="2" y="3" width="12" height="3" rx="1"/><rect x="2" y="10" width="12" height="3" rx="1"/><circle cx="4.5" cy="4.5" r=".5" fill="currentColor"/><circle cx="4.5" cy="11.5" r=".5" fill="currentColor"/></svg>;
    case "frontend":  return <svg {...sp}><rect x="2" y="3" width="12" height="9" rx="1"/><path d="M2 6h12"/><circle cx="4" cy="4.5" r=".4" fill="currentColor"/></svg>;
    case "db":        return <svg {...sp}><ellipse cx="8" cy="4" rx="5" ry="1.6"/><path d="M3 4v8c0 .9 2.2 1.6 5 1.6s5-.7 5-1.6V4"/><path d="M3 8c0 .9 2.2 1.6 5 1.6s5-.7 5-1.6"/></svg>;
    case "infra":     return <svg {...sp}><circle cx="8" cy="8" r="2.2"/><path d="M8 1.5v2M8 12.5v2M14.5 8h-2M3.5 8h-2M12.6 3.4l-1.4 1.4M4.8 11.2l-1.4 1.4M12.6 12.6l-1.4-1.4M4.8 4.8 3.4 3.4"/></svg>;
    case "camera":    return <svg {...sp}><rect x="1.5" y="4.5" width="11" height="7" rx="1"/><path d="m12.5 7 2-1.2v4.4L12.5 9z"/></svg>;
    case "sensor":    return <svg {...sp}><circle cx="8" cy="8" r="1.5"/><path d="M5.2 5.2a4 4 0 0 0 0 5.6M10.8 10.8a4 4 0 0 0 0-5.6M3 3a7 7 0 0 0 0 10M13 13a7 7 0 0 0 0-10"/></svg>;
    case "network":   return <svg {...sp}><circle cx="3" cy="8" r="1.5"/><circle cx="13" cy="3" r="1.5"/><circle cx="13" cy="13" r="1.5"/><path d="M4.5 7.3 11.5 3.7M4.5 8.7l7 3.6"/></svg>;
    case "observability": return <svg {...sp}><circle cx="7" cy="7" r="3.5"/><path d="m10 10 3.5 3.5"/></svg>;
    default:          return <svg {...sp}><circle cx="8" cy="8" r="5"/></svg>;
  }
}

// ────────────────────────────────────────────────────────────
// Sustained / spike / recurring indicator (16px)
function StateIcon({ kind, size = 16 }) {
  const s = size;
  if (kind === "sustained") {
    // amber flame
    return <svg width={s} height={s} viewBox="0 0 16 16" fill="none" aria-label="sustained">
      <path d="M8 14.5c-2.4 0-4.5-1.5-4.5-4 0-1.4.9-2.5 1.6-3.1.4-.3.6 0 .6.3 0 .9.4 1.4.9 1.4.7 0 .8-.7.6-1.7-.4-2 .4-4 2-5.1.4-.3.7 0 .6.4-.2 1.5.6 2.3 1.5 3.2 1 1 2.2 2.4 2.2 4.6 0 2.5-2.1 4-5.5 4Z"
        fill="rgba(240,160,80,.18)" stroke="#f0a050" strokeWidth="1.2"/>
    </svg>;
  }
  if (kind === "spike") {
    // gray lightning
    return <svg width={s} height={s} viewBox="0 0 16 16" fill="none" aria-label="transient spike">
      <path d="M9 1.5 3.5 9h3.7L7 14.5 12.5 7H8.8L9 1.5Z"
        fill="rgba(136,144,160,.15)" stroke="#8890a0" strokeWidth="1.2" strokeLinejoin="round"/>
    </svg>;
  }
  if (kind === "recurring") {
    // blue repeat arrow
    return <svg width={s} height={s} viewBox="0 0 16 16" fill="none" aria-label="recurring">
      <path d="M3 7a5 5 0 0 1 9-3M13 9a5 5 0 0 1-9 3" stroke="#4ea8de" strokeWidth="1.3" strokeLinecap="round"/>
      <path d="M12 1.5V4h-2.5M4 14.5V12h2.5" stroke="#4ea8de" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>;
  }
  return null;
}

// ────────────────────────────────────────────────────────────
// Misc tiny icons
const Icon = {
  copy: (p) => <svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" {...p}><rect x="5" y="5" width="9" height="9" rx="1.5"/><path d="M3 11V3a1 1 0 0 1 1-1h7"/></svg>,
  chevR: (p) => <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.7" {...p}><path d="m6 4 4 4-4 4"/></svg>,
  chevD: (p) => <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.7" {...p}><path d="m4 6 4 4 4-4"/></svg>,
  ext:  (p) => <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" {...p}><path d="M9 3h4v4M13 3 7 9M11 9v3.5A1.5 1.5 0 0 1 9.5 14h-6A1.5 1.5 0 0 1 2 12.5v-6A1.5 1.5 0 0 1 3.5 5H7"/></svg>,
  arrowL: (p) => <svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" {...p}><path d="m10 4-4 4 4 4M6 8h8"/></svg>,
  check: (p) => <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.7" {...p}><path d="m3.5 8.5 3 3 6-7"/></svg>,
  filter: (p) => <svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" {...p}><path d="M2 3h12l-4.5 6V14L6.5 12V9z"/></svg>,
  search: (p) => <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" {...p}><circle cx="7" cy="7" r="4.5"/><path d="m11 11 3 3"/></svg>,
  x: (p) => <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" {...p}><path d="m4 4 8 8M12 4l-8 8"/></svg>,
  copy2: (p) => <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" {...p}><rect x="5" y="5" width="9" height="9" rx="1.5"/><path d="M3 11V3a1 1 0 0 1 1-1h7"/></svg>,
  thumbUp: (p) => <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" {...p}><path d="M7 11v9H3v-9zM7 11l4-8a2 2 0 0 1 3 2v4h5a2 2 0 0 1 2 2.3l-1.2 6A2 2 0 0 1 17.8 19H7"/></svg>,
  thumbDown: (p) => <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" {...p}><path d="M7 13V4h-4v9zM7 13l4 8a2 2 0 0 0 3-2v-4h5a2 2 0 0 0 2-2.3l-1.2-6A2 2 0 0 0 17.8 5H7"/></svg>,
  flame: (p) => <StateIcon kind="sustained" {...p}/>,
  bolt: (p)  => <StateIcon kind="spike" {...p}/>,
  loop: (p)  => <StateIcon kind="recurring" {...p}/>,
};

// ────────────────────────────────────────────────────────────
// Top bar — shared by dashboard and detail page
function TopBar({ uptimeSec = 47812, openAlerts = 7, emailed24h = 12, shelved24h = 38, medianLatency = 4.3, page = "dashboard", onBack }) {
  const h = Math.floor(uptimeSec / 3600);
  const m = Math.floor((uptimeSec % 3600) / 60);
  const s = uptimeSec % 60;
  const uptime = `${h}h ${String(m).padStart(2,'0')}m ${String(s).padStart(2,'0')}s`;
  const nowLocal = window.CIRES_NOW_LOCAL || "2026-05-22 16:45:08";
  return (
    <div style={{
      background: "var(--bg-soft)",
      borderBottom: "1px solid var(--border)",
      padding: "12px 22px",
      display: "flex", alignItems: "center", gap: 22,
      position: "sticky", top: 0, zIndex: 10,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <div style={{
          width: 26, height: 26, borderRadius: 7,
          background: "linear-gradient(135deg, #4ea8de, #b07ee8)",
          display: "grid", placeItems: "center",
          position: "relative",
        }}>
          <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="#0f1117" strokeWidth="2" strokeLinecap="round">
            <circle cx="8" cy="8" r="2"/>
            <path d="M3 8a5 5 0 0 1 10 0M1 8a7 7 0 0 1 14 0"/>
          </svg>
        </div>
        <div style={{ display: "flex", flexDirection: "column", lineHeight: 1.1 }}>
          <div style={{ fontSize: 14.5, fontWeight: 600 }}>Observability · AI RCA</div>
          <div style={{ fontSize: 11, color: "var(--muted)", letterSpacing: 0.04 }}>
            {page === "dashboard" ? "Triage Dashboard" : "Alert Detail"}
          </div>
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 8, marginLeft: 4 }}>
        <span className="live-dot"></span>
        <span style={{ fontSize: 12, color: "var(--text-soft)" }}>Live</span>
        <span className="mono" style={{ fontSize: 11.5, color: "var(--muted)" }}>{uptime}</span>
      </div>

      <div style={{ display: "flex", flexDirection: "column", lineHeight: 1.15, paddingLeft: 14, borderLeft: "1px solid var(--border)" }}>
        <span style={{ fontSize: 10.5, color: "var(--muted)", textTransform: "uppercase", letterSpacing: 0.08 }}>Now · Tangier</span>
        <span className="mono" style={{ fontSize: 13, color: "var(--text)", fontFeatureSettings: '"tnum"' }}>{nowLocal}</span>
      </div>

      <div style={{ flex: 1 }}></div>

      <Stat label="Open" value={openAlerts} accent="var(--accent-red)"/>
      <Stat label="Emailed 24h" value={emailed24h} accent="var(--accent-orange)"/>
      <Stat label="Shelved 24h" value={shelved24h} accent="var(--accent-yellow)"/>
      <Stat label="LLM p50" value={`${medianLatency}s`} accent="var(--accent-purple)"/>

      <ThemeToggle/>

      <div style={{
        width: 30, height: 30, borderRadius: "50%",
        background: "linear-gradient(135deg, #b07ee8, #40d0d0)",
        display: "grid", placeItems: "center",
        fontSize: 12, fontWeight: 600, color: "#0f1117", marginLeft: 6,
      }}>YB</div>
    </div>
  );
}

function Stat({ label, value, accent }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", lineHeight: 1.1, gap: 2 }}>
      <span style={{ fontSize: 10.5, color: "var(--muted)", textTransform: "uppercase", letterSpacing: 0.08 }}>{label}</span>
      <span style={{ fontSize: 16, fontWeight: 600, color: accent, fontFeatureSettings: '"tnum"' }}>{value}</span>
    </div>
  );
}

// Make available globally to other Babel scripts
Object.assign(window, {
  EnvPill, VerdictPill, SeverityPill, NsPill, CompPill,
  ServiceIcon, StateIcon, Icon, TopBar, Stat,
  ENV_STYLES, VERDICT_STYLES, SEVERITY_STYLES, VERDICT_DOT,
  useTheme, ThemeToggle,
});
