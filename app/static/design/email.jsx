/* global React, EnvPill, VerdictPill, SeverityPill, NsPill, CompPill, ServiceIcon, StateIcon, Icon */
// CIRES — Escalation email template (desktop + mobile)

function EmailClientChrome({ children, width, label }) {
  return (
    <div style={{
      width: width,
      background: "#1a1d24",
      borderRadius: 14,
      boxShadow: "0 30px 70px rgba(0,0,0,.5), 0 0 0 1px rgba(255,255,255,.04)",
      overflow: "hidden",
      fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
    }}>
      {/* Email client toolbar */}
      <div style={{
        background: "#23262e", padding: "10px 14px",
        display: "flex", alignItems: "center", gap: 8,
        borderBottom: "1px solid #2c2f37",
        fontSize: 12, color: "#9ba0ab",
      }}>
        <div style={{ display: "flex", gap: 6 }}>
          <span style={{ width: 11, height: 11, borderRadius: "50%", background: "#ff5f57" }}></span>
          <span style={{ width: 11, height: 11, borderRadius: "50%", background: "#febc2e" }}></span>
          <span style={{ width: 11, height: 11, borderRadius: "50%", background: "#28c840" }}></span>
        </div>
        <span style={{ marginLeft: 14 }}>{label}</span>
        <span style={{ flex: 1 }}></span>
        <span style={{ fontSize: 11, color: "#5b6072" }}>16:47</span>
      </div>

      {/* Mail header (from/to/subject) */}
      <div style={{ background: "#1f222a", padding: "14px 20px", borderBottom: "1px solid #2c2f37", color: "#c0c5d0", fontSize: 12.5 }}>
        <div style={{ display: "flex", gap: 10, marginBottom: 6 }}>
          <span style={{ color: "#8890a0", width: 50 }}>From</span>
          <span style={{ color: "#e4e6ee" }}>Observability · AI RCA</span>
          <span style={{ color: "#5b6072", fontFamily: "var(--font-mono)", fontSize: 11.5 }}>&lt;triage@obs.internal&gt;</span>
        </div>
        <div style={{ display: "flex", gap: 10, marginBottom: 6 }}>
          <span style={{ color: "#8890a0", width: 50 }}>To</span>
          <span style={{ color: "#e4e6ee" }}>on-call-sre@obs.internal</span>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <span style={{ color: "#8890a0", width: 50 }}>Subject</span>
          <span style={{ color: "#e4e6ee", fontWeight: 500 }}>
            [<span style={{ color: "#f3a4ad" }}>prod</span>] [<span style={{ color: "#9fcdee" }}>app</span>] [<span style={{ color: "#f3a4ad" }}>ESCALATE</span>] High p95 latency on Kong gateway
          </span>
        </div>
      </div>

      {/* Body */}
      {children}
    </div>
  );
}

function EmailBody({ a, mobile }) {
  return (
    <div style={{
      background: "#0f1117",
      color: "#e4e6ee",
      padding: mobile ? "20px 18px 24px" : "28px 30px 32px",
      fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
    }}>
      {/* Banner */}
      <div style={{
        background: "linear-gradient(180deg, rgba(224,96,112,.10), rgba(224,96,112,.02))",
        border: "1px solid rgba(224,96,112,.35)",
        borderRadius: 12,
        padding: mobile ? "14px 16px" : "16px 20px",
        marginBottom: 22,
        display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap",
      }}>
        <span style={{ display: "inline-flex" }}><StateIcon kind="sustained" size={20}/></span>
        <VerdictPill v="ESCALATE" size="lg"/>
        <SeverityPill s="critical" size="lg"/>
        <span style={{ fontSize: 12, color: "#8890a0" }}>Active for <span style={{ color: "#f3c891" }}>{a.activeFor}</span></span>
      </div>

      {/* Identity pills */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 16 }}>
        <EnvPill env={a.env}/>
        <NsPill ns={a.namespace}/>
        <span className="pill pill-gray" style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
          <ServiceIcon type={a.serviceType}/> {a.serviceType}
        </span>
        <CompPill c={a.component}/>
      </div>

      {/* WHAT */}
      <h1 style={{
        margin: "0 0 4px",
        fontSize: mobile ? 20 : 24,
        fontWeight: 600,
        color: "#e4e6ee",
        lineHeight: 1.3,
        letterSpacing: -0.01,
      }}>
        {a.alertPlain}
      </h1>
      <div style={{ fontSize: 12.5, color: "#8890a0", marginBottom: 20 }}>
        Fired {a.relTime} · alert <span style={{ fontFamily: "var(--font-mono)", color: "#c0c5d0" }}>{a.id}</span>
      </div>

      {/* Three blocks */}
      <div style={{
        display: mobile ? "flex" : "grid",
        flexDirection: "column",
        gridTemplateColumns: "1.4fr 1.6fr 0.9fr",
        gap: 12, marginBottom: 22,
      }}>
        <EmailBlock label="Why">
          <div style={{ fontSize: 14, lineHeight: 1.5, color: "#e4e6ee" }}>
            Kong upstream pool to <strong style={{ color: "#e8dca0", fontFamily: "var(--font-mono)", fontWeight: 600 }}>spring-boot</strong> is near saturation; p95 latency above baseline for 6+ hours.
          </div>
        </EmailBlock>

        <EmailBlock label="Suggested action">
          <div style={{
            background: "#0a0c11", border: "1px solid #2a2d3a",
            borderRadius: 6, padding: "8px 10px",
            fontFamily: "var(--font-mono)", fontSize: 12, color: "#e4e6ee",
            display: "flex", alignItems: "center", gap: 8,
            wordBreak: "break-all",
          }}>
            <span style={{ color: "#40d0d0" }}>$</span>
            <span style={{ flex: 1 }}>kubectl rollout restart deploy/kong -n app</span>
          </div>
          <button style={emailBtn("ghost")}>Copy</button>
        </EmailBlock>

        <EmailBlock label="Severity">
          <SeverityPill s="critical" size="lg"/>
          <div style={{
            display: "inline-flex", alignItems: "center", gap: 6,
            marginTop: 6, fontSize: 11.5, color: "#f3c891",
          }}>
            <StateIcon kind="sustained" size={14}/> sustained 6h+
          </div>
        </EmailBlock>
      </div>

      {/* Buttons row */}
      <div style={{ display: "flex", gap: 8, marginBottom: 18, flexWrap: "wrap" }}>
        <a style={emailBtn("primary", mobile)}>View on dashboard →</a>
        <a style={emailBtn("default", mobile)}>Open Grafana ↗</a>
        <a style={emailBtn("default", mobile)}>Open Loki ↗</a>
        <a style={emailBtn("default", mobile)}>Rate this alert</a>
      </div>

      {/* Footer */}
      <div style={{
        marginTop: 22, paddingTop: 14, borderTop: "1px solid #2a2d3a",
        fontSize: 11.5, color: "#5b6172", lineHeight: 1.6,
        display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 6,
      }}>
        <span>Alert <span style={{ fontFamily: "var(--font-mono)" }}>{a.id}</span> · {a.timeLocal} Tangier (UTC+01:00)</span>
        <span>AI RCA Triage Platform <span style={{ fontFamily: "var(--font-mono)" }}>v0.1.0</span></span>
      </div>
    </div>
  );
}

function EmailBlock({ label, children }) {
  return (
    <div style={{
      background: "#1a1d27", border: "1px solid #2a2d3a",
      borderRadius: 10, padding: "12px 14px",
      display: "flex", flexDirection: "column", gap: 8,
    }}>
      <div style={{
        fontSize: 10.5, fontWeight: 600, color: "#8890a0",
        textTransform: "uppercase", letterSpacing: 0.1,
      }}>{label}</div>
      {children}
    </div>
  );
}

function emailBtn(variant, mobile) {
  const base = {
    display: "inline-flex", alignItems: "center", gap: 6,
    padding: mobile ? "10px 14px" : "9px 14px",
    borderRadius: 8, fontSize: 13, fontWeight: 500,
    border: "1px solid #2a2d3a", background: "#1a1d27",
    color: "#e4e6ee", textDecoration: "none", cursor: "pointer",
    width: mobile ? "100%" : "auto", justifyContent: mobile ? "center" : "flex-start",
  };
  if (variant === "primary") return {
    ...base,
    background: "rgba(78,168,222,.18)",
    borderColor: "rgba(78,168,222,.45)",
    color: "#b9dcf2",
  };
  if (variant === "ghost") return {
    ...base, background: "transparent", borderColor: "#2a2d3a",
    fontSize: 11.5, padding: "5px 10px", color: "#8890a0",
    alignSelf: "flex-start", width: "auto",
  };
  return base;
}

function EmailDesktop() {
  const a = window.CIRES_ALERTS[0];
  return (
    <div className="cires" style={{ background: "#0a0b0f", padding: 28, minHeight: "100%" }}>
      <EmailClientChrome width={680} label="Inbox · ESCALATE">
        <EmailBody a={a}/>
      </EmailClientChrome>
    </div>
  );
}

function EmailMobile() {
  const a = window.CIRES_ALERTS[0];
  return (
    <div className="cires" style={{ background: "#0a0b0f", padding: 16, minHeight: "100%", display: "flex", justifyContent: "center" }}>
      <EmailClientChrome width={380} label="Mail">
        <EmailBody a={a} mobile/>
      </EmailClientChrome>
    </div>
  );
}

Object.assign(window, { EmailDesktop, EmailMobile });
