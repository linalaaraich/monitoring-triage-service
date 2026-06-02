/* global React, EnvPill, VerdictPill, SeverityPill, NsPill, CompPill, ServiceIcon, StateIcon, Icon, TopBar */
// CIRES — Alert detail page

const { useState: useDetailState } = React;

function DetailHeader({ a }) {
  return (
    <div style={{
      background: "var(--bg-soft)",
      borderBottom: "1px solid var(--border)",
      padding: "16px 28px",
      display: "flex", alignItems: "flex-start", gap: 18,
      position: "sticky", top: 60, zIndex: 8,
    }}>
      <button className="btn ghost" style={{ color: "var(--muted)", marginTop: 2 }}>
        <Icon.arrowL/>
      </button>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
          <StateIcon kind={a.indicator}/>
          <span className="mono" style={{ fontSize: 11.5, color: "var(--muted)", letterSpacing: 0.04 }}>
            {a.id}
          </span>
          <span style={{ color: "var(--muted-2)" }}>·</span>
          <EnvPill env={a.env}/>
          <NsPill ns={a.namespace}/>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 6, color: "var(--text-soft)", fontSize: 12 }}>
            <span style={{ color: "var(--muted)", display: "inline-flex" }}><ServiceIcon type={a.serviceType}/></span>
            {a.serviceType}
          </span>
          <CompPill c={a.component}/>
        </div>
        <h1 style={{ margin: 0, fontSize: 22, fontWeight: 600, letterSpacing: -0.01 }}>
          {a.alertPlain}
        </h1>
        <div style={{
          display: "flex", alignItems: "center", gap: 12, marginTop: 8,
          fontSize: 12.5, color: "var(--muted)", flexWrap: "wrap",
        }}>
          <VerdictPill v={a.verdict} size="lg"/>
          <SeverityPill s={a.severity} size="lg"/>
          <span>·</span>
          <span>Fired <span className="mono" style={{ color: "var(--text-soft)" }}>{a.timeLocal || a.relTime}</span> <span style={{ color: "var(--muted-2)" }}>Tangier (UTC+01:00)</span></span>
          <span>·</span>
          <span>Active for <span style={{ color: "var(--accent-orange)" }}>{a.activeFor}</span></span>
          <span>·</span>
          <span>Fingerprint <span className="mono" style={{ color: "var(--text-soft)" }}>{a.fingerprint}</span></span>
        </div>
      </div>
      {/* 2026-06-02 — wire real hrefs from the server-injected URLs.
          window.CIRES_LINKS is populated by the /dashboard/alert/{id}
          route handler with grafana_url / loki_url / jaeger_url out of
          app.config.settings. Falls back to "#" if not injected so the
          design canvas still renders standalone. */}
      <div style={{ display: "flex", gap: 8, marginTop: 2 }}>
        <a className="btn" href={(window.CIRES_LINKS && window.CIRES_LINKS.grafana) || "#"} target="_blank" rel="noopener noreferrer">Grafana <Icon.ext/></a>
        <a className="btn" href={(window.CIRES_LINKS && window.CIRES_LINKS.loki) || "#"} target="_blank" rel="noopener noreferrer">Loki <Icon.ext/></a>
        <a className="btn" href={(window.CIRES_LINKS && window.CIRES_LINKS.jaeger) || "#"} target="_blank" rel="noopener noreferrer">Jaeger <Icon.ext/></a>
      </div>
    </div>
  );
}

function CauseSection({ a }) {
  const parts = a.reason.split(new RegExp(`(${a.boldSubject || '___NONE___'})`));
  return (
    <section style={{ marginBottom: 24 }}>
      <div className="section-label">Cause</div>
      <div className="callout">
        <div style={{ fontSize: 18, lineHeight: 1.45, color: "var(--text)", maxWidth: 820 }}>
          {parts.map((p, i) => p === a.boldSubject
            ? <strong key={i} className="mono" style={{ color: "var(--accent-yellow)", fontWeight: 600, padding: "0 2px" }}>{p}</strong>
            : <React.Fragment key={i}>{p}</React.Fragment>
          )}
        </div>
        <div style={{ marginTop: 10, fontSize: 12.5, color: "var(--muted)" }}>
          LLM confidence <span style={{ color: "var(--text-soft)" }}>{Math.round((a.confidence || 0)*100)}%</span> · quality <span style={{ color: "var(--accent-green)" }}>{a.quality}</span> · {a.tags.slice(0,3).map(t => <span key={t} style={{ marginRight: 6, color: "var(--text-soft)" }}>#{t}</span>)}
        </div>
      </div>
    </section>
  );
}

function ActionSection({ a }) {
  return (
    <section style={{ marginBottom: 24 }}>
      <div className="section-label">Suggested actions</div>
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {(a.actions || []).map((act, i) => (
          <div key={i} className="card" style={{ padding: 14, display: "flex", flexDirection: "column", gap: 10 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
              <span className="codechip" style={{ flex: 1, minWidth: 0 }}>
                <span className="cmd-prefix">$</span>
                <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{act.cmd}</span>
              </span>
              <button className="btn sm"><Icon.copy2/> Copy</button>
              <button className="btn sm primary">Run in shell</button>
            </div>
            {act.why && <div style={{ fontSize: 13, color: "var(--text-soft)", lineHeight: 1.5 }}>
              <span style={{ color: "var(--muted)" }}>Why:</span> {act.why}
            </div>}
          </div>
        ))}
      </div>
    </section>
  );
}

function HistorySection({ a }) {
  const history = a.history && a.history.length ? a.history : [
    { time: "now", verdict: a.verdict, delta: "first seen" },
  ];
  return (
    <section style={{ marginBottom: 24 }}>
      <div className="section-label">Incident history · {history.length === 1 ? "first fire" : history.length + " fires"}</div>
      <div className="card" style={{ padding: "18px 22px" }}>
        {history.length === 1 ? (
          <div style={{ fontSize: 13.5, color: "var(--text-soft)" }}>
            First seen <strong style={{ color: "var(--text)" }}>{a.relTime}</strong>. No prior history for this fingerprint.
          </div>
        ) : (
          <div style={{ position: "relative" }}>
            <div style={{
              position: "absolute", left: 8, top: 6, bottom: 6,
              width: 2, background: "var(--border-hi)", borderRadius: 2,
            }}></div>
            {history.map((h, i) => (
              <div key={i} style={{ display: "flex", gap: 14, padding: "6px 0 14px 0", position: "relative" }}>
                <div style={{
                  width: 18, height: 18, borderRadius: "50%",
                  background: window.VERDICT_DOT[h.verdict] || "#8890a0",
                  boxShadow: i === 0 ? `0 0 0 4px rgba(${h.verdict==='ESCALATE' ? '224,96,112' : '136,144,160'},.18)` : "none",
                  flexShrink: 0, marginLeft: -1, zIndex: 1,
                  border: "3px solid var(--card)",
                }}></div>
                <div style={{ flex: 1, paddingTop: 1 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 2 }}>
                    <span style={{ fontSize: 14, fontWeight: 500, color: "var(--text)" }}>{h.time}</span>
                    <VerdictPill v={h.verdict}/>
                  </div>
                  <div style={{ fontSize: 12.5, color: "var(--muted)" }}>{h.delta}</div>
                </div>
                {i === 0 && <span style={{ fontSize: 11, color: "var(--muted)", padding: "2px 8px", borderRadius: 4, background: "var(--bg-soft)", border: "1px solid var(--border)", height: "fit-content" }}>current</span>}
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}

function Drain3Section({ a }) {
  const d = a.drain3;
  if (!d) return null;

  const fmt = (n) => n >= 1_000_000 ? (n/1_000_000).toFixed(1)+"M" : n >= 1000 ? (n/1000).toFixed(1)+"k" : String(n);

  return (
    <section style={{ marginBottom: 24 }}>
      <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", marginBottom: 10 }}>
        <div className="section-label" style={{ margin: 0, display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 6, color: "var(--accent-yellow)" }}>
            <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4"><path d="M2 3h12M2 8h12M2 13h12" strokeDasharray="2 1.5"/></svg>
            Drain3 log-template analysis
          </span>
          <span style={{ color: "var(--muted-2)", fontWeight: 400, letterSpacing: 0 }}>· inline log-template miner</span>
        </div>
        <a className="btn sm" style={{ color: "var(--muted)" }}>Open Drain3 panel <Icon.ext/></a>
      </div>

      {/* Stat strip */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 12 }}>
        <D3Stat label="Templates learned" value={fmt(d.learnedTotal)} accent="var(--accent-purple)"/>
        <D3Stat label="Lines ingested 24h" value={fmt(d.linesIngested24h)} accent="var(--accent-cyan)"/>
        <D3Stat label="Anomaly rate" value={(d.anomalyRate*100).toFixed(2)+"%"}
          accent={d.anomalyRate > 0.05 ? "var(--accent-orange)" : "var(--accent-green)"}/>
        <D3Stat label="Matched template" value={d.matchedTemplate.id} mono accent="var(--accent-yellow)"/>
      </div>

      {/* Matched template card */}
      <div className="card" style={{ padding: 16, marginBottom: 12 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
          <span className="pill pill-yellow" style={{ fontFamily: "var(--font-mono)" }}>{d.matchedTemplate.id}</span>
          <span className="pill pill-red">anomaly</span>
          <span style={{ fontSize: 12, color: "var(--muted)" }}>
            {d.matchedTemplate.nowPerHour}/h now · baseline {d.matchedTemplate.usuallyPerHour}/h · <span style={{ color: "var(--accent-orange)" }}>{d.matchedTemplate.deltaX}× above</span>
          </span>
          <div style={{ flex: 1 }}></div>
          <span style={{ fontSize: 11.5, color: "var(--muted)" }}>
            First seen <span className="mono" style={{ color: "var(--text-soft)" }}>{d.matchedTemplate.firstSeen}</span>
          </span>
        </div>

        <div style={{
          fontFamily: "var(--font-mono)", fontSize: 12.5,
          background: "var(--code-bg)", border: "1px solid var(--border)",
          padding: "10px 14px", borderRadius: 8, lineHeight: 1.6,
          color: "var(--text)", overflowX: "auto",
        }}>
          <span style={{ color: "var(--muted)" }}>pattern  </span>
          <TemplateText text={d.matchedTemplate.pattern}/>
          <div style={{ marginTop: 6 }}>
            <span style={{ color: "var(--muted)" }}>sample   </span>
            <span style={{ color: "var(--accent-cyan)" }}>{d.matchedTemplate.sample}</span>
          </div>
        </div>

        {/* Sparkline */}
        <D3Sparkline data={[2,3,4,5,8,12,28,52,98,180,260,312]}/>
      </div>

      {/* Related templates */}
      <div className="card" style={{ padding: 14 }}>
        <div style={{
          fontSize: 11, color: "var(--muted)", textTransform: "uppercase",
          letterSpacing: 0.1, fontWeight: 600, marginBottom: 10,
        }}>Related templates in this window</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {d.relatedTemplates.map((t) => (
            <div key={t.id} style={{
              display: "flex", alignItems: "center", gap: 12,
              padding: "7px 10px", borderRadius: 8,
              background: t.anomaly ? "rgba(240,160,80,.05)" : "transparent",
              border: "1px solid " + (t.anomaly ? "rgba(240,160,80,.22)" : "transparent"),
            }}>
              <span className="mono" style={{ fontSize: 11.5, color: t.anomaly ? "var(--accent-orange)" : "var(--muted)", width: 56 }}>{t.id}</span>
              {t.anomaly
                ? <span className="pill pill-amber" style={{ fontSize: 10.5, padding: "1px 7px" }}>anomaly</span>
                : <span className="pill pill-gray" style={{ fontSize: 10.5, padding: "1px 7px" }}>normal</span>}
              <span className="mono" style={{ fontSize: 12, color: "var(--text-soft)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {t.pattern}
              </span>
              <span style={{ fontSize: 11.5, color: "var(--muted)", whiteSpace: "nowrap" }}>
                <span style={{ color: "var(--text-soft)" }} className="mono">{t.freq}</span>/h
                <span style={{ color: "var(--muted-2)" }}> · base {t.baseline}</span>
              </span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function D3Stat({ label, value, accent, mono }) {
  return (
    <div className="card" style={{ padding: "10px 14px" }}>
      <div style={{ fontSize: 10.5, color: "var(--muted)", textTransform: "uppercase", letterSpacing: 0.08, marginBottom: 4 }}>{label}</div>
      <div className={mono ? "mono" : ""} style={{ fontSize: 18, fontWeight: 600, color: accent || "var(--text)", fontFeatureSettings: '"tnum"' }}>{value}</div>
    </div>
  );
}

function TemplateText({ text }) {
  // Highlight <*> wildcards
  const parts = text.split(/(<\*>)/g);
  return <span>{parts.map((p, i) =>
    p === "<*>"
      ? <span key={i} style={{ color: "var(--accent-purple)", background: "rgba(176,126,232,.10)", padding: "0 4px", borderRadius: 3 }}>{p}</span>
      : <span key={i} style={{ color: "var(--text)" }}>{p}</span>
  )}</span>;
}

function D3Sparkline({ data }) {
  const w = 100, h = 32, max = Math.max(...data);
  const step = w / (data.length - 1);
  const points = data.map((v, i) => `${i*step},${h - (v/max)*h}`).join(" ");
  const area = `0,${h} ${points} ${w},${h}`;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 14, marginTop: 12, paddingTop: 10, borderTop: "1px dashed var(--border)" }}>
      <div style={{ fontSize: 11, color: "var(--muted)", textTransform: "uppercase", letterSpacing: 0.08 }}>last 12h</div>
      <svg viewBox={`0 0 ${w} ${h}`} width="200" height={h} preserveAspectRatio="none">
        <polygon points={area} fill="rgba(240,160,80,.15)"/>
        <polyline points={points} fill="none" stroke="#f0a050" strokeWidth="1.4" strokeLinejoin="round"/>
      </svg>
      <div style={{ fontSize: 11.5, color: "var(--muted)" }}>
        <span style={{ color: "var(--accent-orange)" }}>↑</span> sharp ramp in last 2h, no prior occurrence in baseline window
      </div>
    </div>
  );
}

function EvidenceSection({ a }) {
  const SOURCE_LABEL = {
    prom:   { name: "Prometheus", color: "var(--accent-orange)" },
    loki:   { name: "Loki",       color: "var(--accent-cyan)" },
    jaeger: { name: "Jaeger",     color: "var(--accent-purple)" },
    drain3: { name: "Drain3",     color: "var(--accent-yellow)" },
  };
  return (
    <section style={{ marginBottom: 24 }}>
      <div className="section-label">Evidence cited · {a.evidence ? a.evidence.length : 0} sources</div>
      <div className="card">
        {(a.evidence || []).map((e, i) => {
          const meta = SOURCE_LABEL[e.source] || { name: "Other", color: "var(--muted)" };
          return (
            <div key={i} style={{
              padding: "13px 18px",
              borderBottom: i < a.evidence.length - 1 ? "1px solid var(--border)" : "none",
              display: "flex", gap: 14, alignItems: "center",
            }}>
              <span style={{
                fontSize: 10.5, fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.08,
                color: meta.color, width: 80, flexShrink: 0,
              }}>{meta.name}</span>
              <span style={{ flex: 1, fontSize: 13.5, color: "var(--text)", lineHeight: 1.5 }}>{e.text}</span>
              <a className="btn sm">View in {e.link} <Icon.ext/></a>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function ReasoningSection({ a, expanded, onToggle }) {
  return (
    <section style={{ marginBottom: 24 }}>
      <button onClick={onToggle} style={{
        display: "flex", alignItems: "center", gap: 10,
        background: "transparent", border: 0, padding: 0,
        cursor: "pointer", color: "var(--text-soft)",
        fontFamily: "inherit", fontSize: 13,
      }}>
        <span style={{ transform: expanded ? "rotate(90deg)" : "none", transition: "transform .12s", display: "inline-flex" }}>
          <Icon.chevR/>
        </span>
        <span style={{ textTransform: "uppercase", letterSpacing: 0.1, fontSize: 11, fontWeight: 600, color: "var(--muted)" }}>
          {expanded ? "Hide" : "Show"} reasoning steps
        </span>
        <span style={{ fontSize: 12, color: "var(--muted-2)" }}>· {a.reasoning.length} steps · LLM thought</span>
      </button>
      {expanded && (
        <ol style={{
          margin: "12px 0 0", padding: "16px 24px 16px 40px",
          background: "var(--card)", border: "1px solid var(--border)", borderRadius: 10,
          listStyle: "none", counterReset: "step",
        }}>
          {a.reasoning.map((step, i) => (
            <li key={i} style={{
              counterIncrement: "step",
              padding: "8px 0", borderBottom: i < a.reasoning.length - 1 ? "1px dashed var(--border)" : "none",
              display: "flex", gap: 14, alignItems: "baseline",
              color: "var(--text)", fontSize: 14, lineHeight: 1.5,
            }}>
              <span style={{
                width: 24, height: 24, borderRadius: "50%",
                background: "rgba(176,126,232,.12)",
                color: "var(--accent-purple)",
                display: "grid", placeItems: "center",
                fontSize: 11.5, fontWeight: 600, flexShrink: 0,
                border: "1px solid rgba(176,126,232,.35)",
              }}>{i+1}</span>
              <span>{step}</span>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

function RelatedSidebar({ a }) {
  return (
    <aside style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      <div>
        <div className="section-label">Related alerts</div>
        <div className="card" style={{ overflow: "hidden" }}>
          {/* 2026-06-02 — wire real hrefs so each related alert is
              clickable. The {r.id} is the 8-char short id the
              /dashboard/alert/{short_id} route resolves. */}
          {(a.related || []).map((r, i) => (
            <a key={r.id} href={`/dashboard/alert/${r.id}`} style={{
              display: "block", padding: "12px 14px",
              borderBottom: i < a.related.length - 1 ? "1px solid var(--border)" : "none",
              textDecoration: "none", cursor: "pointer",
              color: "inherit",
            }} className="lift">
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 5 }}>
                <VerdictPill v={r.verdict}/>
                <span className="mono" style={{ fontSize: 10.5, color: "var(--muted-2)" }}>{r.id}</span>
              </div>
              <div style={{ fontSize: 13, color: "var(--text)", lineHeight: 1.4, marginBottom: 3 }}>
                {r.title}
              </div>
              <div style={{ fontSize: 11.5, color: "var(--muted)" }}>{r.time}</div>
            </a>
          ))}
        </div>
      </div>

      <div>
        <div className="section-label">Deploy context</div>
        <div className="card" style={{ padding: 14, position: "relative" }}>
          <div style={{
            position: "absolute", top: 12, right: 12,
            fontSize: 10, color: "var(--accent-purple)",
            background: "rgba(176,126,232,.1)", border: "1px solid rgba(176,126,232,.35)",
            padding: "2px 7px", borderRadius: 4, letterSpacing: 0.06,
          }}>BETA</div>
          {a.deploy ? (
            <React.Fragment>
              <div style={{ fontSize: 12, color: "var(--accent-orange)", marginBottom: 8, fontWeight: 500 }}>
                Possibly related deploy
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                <span className="codechip" style={{ padding: "3px 8px", fontSize: 11.5 }}>{a.deploy.sha}</span>
                <span style={{ fontSize: 12.5, color: "var(--text-soft)" }}>by {a.deploy.author}</span>
              </div>
              <div style={{ fontSize: 12, color: "var(--muted)", marginBottom: 12 }}>
                Pushed <span style={{ color: "var(--text-soft)" }}>{a.deploy.when}</span> · <span className="mono">{a.deploy.repo}</span>
              </div>
              <a className="btn sm" style={{ width: "100%", justifyContent: "center" }}>View commit <Icon.ext/></a>
            </React.Fragment>
          ) : (
            <div style={{ fontSize: 13, color: "var(--muted)" }}>No deploy within ±30 min.</div>
          )}
        </div>
      </div>

      <div>
        <div className="section-label">Feedback</div>
        <div className="card" style={{ padding: 14 }}>
          <div style={{ fontSize: 13.5, color: "var(--text)", marginBottom: 12 }}>Was this alert useful?</div>
          <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
            <button className="btn lift" style={{ flex: 1, justifyContent: "center", color: "var(--accent-green)" }}>
              <Icon.thumbUp/>
            </button>
            <button className="btn lift" style={{ flex: 1, justifyContent: "center", color: "var(--accent-red)" }}>
              <Icon.thumbDown/>
            </button>
          </div>
          <a className="btn sm ghost" style={{ width: "100%", justifyContent: "center", color: "var(--muted)" }}>
            Open full feedback form →
          </a>
        </div>
      </div>
    </aside>
  );
}

function RawDataSection({ a, expanded, onToggle }) {
  return (
    <section style={{ marginBottom: 24 }}>
      <button onClick={onToggle} style={{
        display: "flex", alignItems: "center", gap: 10, width: "100%",
        background: "var(--bg-soft)", border: "1px solid var(--border)",
        padding: "12px 16px", borderRadius: 10,
        cursor: "pointer", color: "var(--text-soft)",
        fontFamily: "inherit", fontSize: 13, textAlign: "left",
      }}>
        <span style={{ transform: expanded ? "rotate(90deg)" : "none", transition: "transform .12s", display: "inline-flex" }}>
          <Icon.chevR/>
        </span>
        <span style={{ textTransform: "uppercase", letterSpacing: 0.1, fontSize: 11, fontWeight: 600, color: "var(--muted)" }}>
          Raw data
        </span>
        <span style={{ flex: 1, fontSize: 12, color: "var(--muted-2)" }}>
          Full UUID · fingerprint · PromQL · raw evidence · LLM RCA prose · IP · timestamps
        </span>
        <span style={{ fontSize: 11, color: "var(--muted-2)", fontFamily: "var(--font-mono)" }}>
          {expanded ? "expanded" : "collapsed"}
        </span>
      </button>
      {expanded && (
        <div style={{
          marginTop: 8, padding: 18, background: "var(--code-bg)",
          border: "1px solid var(--border)", borderRadius: 10,
          fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-soft)",
          lineHeight: 1.7, overflowX: "auto",
        }}>
          <div><span style={{ color: "var(--muted)" }}>uuid:</span> <span style={{ color: "var(--accent-yellow)" }}>{a.uuid}</span></div>
          <div><span style={{ color: "var(--muted)" }}>fingerprint:</span> {a.fingerprint}</div>
          <div><span style={{ color: "var(--muted)" }}>alertname:</span> {a.alertName}</div>
          <div><span style={{ color: "var(--muted)" }}>instance:</span> {a.ip}</div>
          <div><span style={{ color: "var(--muted)" }}>fired_at:</span> {a.timeISO}</div>
          <div style={{ marginTop: 8 }}><span style={{ color: "var(--muted)" }}>promql:</span></div>
          <div style={{ paddingLeft: 18, color: "var(--accent-cyan)" }}>{a.promql}</div>
        </div>
      )}
    </section>
  );
}

function DetailPage({ a, openReasoning = false, openRaw = false }) {
  const [reasoningOpen, setReasoningOpen] = useDetailState(openReasoning);
  const [rawOpen, setRawOpen] = useDetailState(openRaw);
  const [theme] = window.useTheme();
  const [collapsed, setCollapsed] = window.useSidebarCollapsed();

  return (
    <div className="cires" data-theme={theme} style={{ background: "var(--bg)", minHeight: "100%", display: "flex" }}>
      <window.Sidebar active="triage" collapsed={collapsed} onToggleCollapse={() => setCollapsed(!collapsed)}/>
      <div style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
        <TopBar uptimeSec={47812} openAlerts={7} emailed24h={12} shelved24h={38} medianLatency={4.3} page="detail"/>
        <DetailHeader a={a}/>
        <div style={{ padding: "24px 28px 40px", display: "grid", gridTemplateColumns: "1fr 320px", gap: 28, maxWidth: 1480, margin: "0 auto", width: "100%" }}>
          <main>
            <CauseSection a={a}/>
            <ActionSection a={a}/>
            <HistorySection a={a}/>
            <EvidenceSection a={a}/>
            <Drain3Section a={a}/>
            <ReasoningSection a={a} expanded={reasoningOpen} onToggle={()=>setReasoningOpen(!reasoningOpen)}/>
            <RawDataSection a={a} expanded={rawOpen} onToggle={()=>setRawOpen(!rawOpen)}/>
          </main>
          <RelatedSidebar a={a}/>
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { DetailPage });
