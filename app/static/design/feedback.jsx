/* global React, EnvPill, VerdictPill, SeverityPill, NsPill, CompPill, ServiceIcon, StateIcon, Icon */
// CIRES — Operator feedback form

const { useState: useFb } = React;

function Radio({ checked, label, color, onClick }) {
  return (
    <button onClick={onClick} style={{
      display: "inline-flex", alignItems: "center", gap: 8,
      padding: "8px 14px", borderRadius: 8,
      background: checked ? (color || "rgba(78,168,222,.14)") : "var(--card)",
      border: "1px solid " + (checked ? (color === "rgba(107,207,127,.16)" ? "rgba(107,207,127,.5)" : color === "rgba(224,96,112,.16)" ? "rgba(224,96,112,.5)" : "rgba(78,168,222,.5)") : "var(--border)"),
      color: "var(--text)",
      fontSize: 13.5, fontWeight: 500,
      cursor: "pointer", fontFamily: "inherit",
      transition: "all .12s",
    }}>
      <span style={{
        width: 14, height: 14, borderRadius: "50%",
        border: "1.5px solid " + (checked ? (color === "rgba(107,207,127,.16)" ? "#6bcf7f" : color === "rgba(224,96,112,.16)" ? "#e06070" : "#4ea8de") : "var(--border-hi)"),
        display: "grid", placeItems: "center",
      }}>
        {checked && <span style={{
          width: 6, height: 6, borderRadius: "50%",
          background: color === "rgba(107,207,127,.16)" ? "#6bcf7f" : color === "rgba(224,96,112,.16)" ? "#e06070" : "#4ea8de",
        }}/>}
      </span>
      {label}
    </button>
  );
}

function RadioGroup({ question, hint, options, value, onChange }) {
  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 10 }}>
        <div style={{ fontSize: 14.5, fontWeight: 500, color: "var(--text)" }}>{question}</div>
        {hint && <div style={{ fontSize: 12, color: "var(--muted)" }}>{hint}</div>}
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
        {options.map(o => (
          <Radio key={o.value} checked={value === o.value} label={o.label} color={o.color}
                 onClick={() => onChange(o.value)}/>
        ))}
      </div>
    </div>
  );
}

function TagChip({ active, color, label, onClick }) {
  return (
    <button onClick={onClick} style={{
      padding: "5px 11px", borderRadius: 999,
      background: active ? `rgba(${color},.14)` : "var(--card)",
      border: "1px solid " + (active ? `rgba(${color},.5)` : "var(--border)"),
      color: active ? `rgb(${color})` : "var(--text-soft)",
      fontSize: 12, fontWeight: 500,
      cursor: "pointer", fontFamily: "inherit",
      transition: "all .12s",
      display: "inline-flex", alignItems: "center", gap: 6,
    }}>
      {active && <Icon.check style={{ width: 11, height: 11 }}/>}
      {label}
    </button>
  );
}

const TAG_OPTIONS = [
  { v: "noise",                color: "136,144,160", label: "noise" },
  { v: "real-incident",        color: "224,96,112",  label: "real-incident" },
  { v: "misattributed",        color: "240,160,80",  label: "misattributed" },
  { v: "wrong-arch",           color: "240,160,80",  label: "wrong-arch" },
  { v: "good-catch",           color: "107,207,127", label: "good-catch" },
  { v: "shelved-correctly",    color: "78,168,222",  label: "shelved-correctly" },
  { v: "needed-faster-page",   color: "224,96,112",  label: "needed-faster-page" },
  { v: "other",                color: "136,144,160", label: "other" },
];

const YN_OPTS = [
  { value: "yes", label: "Yes", color: "rgba(107,207,127,.16)" },
  { value: "no",  label: "No", color: "rgba(224,96,112,.16)" },
  { value: "partial", label: "Partially", color: "rgba(78,168,222,.14)" },
];
const YN_OPTS_3 = [
  { value: "yes", label: "Yes", color: "rgba(107,207,127,.16)" },
  { value: "no",  label: "No", color: "rgba(224,96,112,.16)" },
  { value: "mixed", label: "Mixed", color: "rgba(78,168,222,.14)" },
];
const YN_OPTS_4 = [
  { value: "yes", label: "Yes", color: "rgba(107,207,127,.16)" },
  { value: "no",  label: "No", color: "rgba(224,96,112,.16)" },
  { value: "na",  label: "N/A", color: "rgba(78,168,222,.14)" },
];

function FeedbackHeader({ a }) {
  return (
    <div style={{
      padding: "20px 24px", borderBottom: "1px solid var(--border)",
      background: "var(--bg-soft)",
    }}>
      <div style={{ fontSize: 11, color: "var(--muted)", textTransform: "uppercase", letterSpacing: 0.1, marginBottom: 8 }}>
        Feedback on alert <span className="mono" style={{ color: "var(--text-soft)" }}>{a.id}</span>
      </div>
      <h1 style={{ margin: 0, fontSize: 22, fontWeight: 600, letterSpacing: -0.01 }}>
        How was this alert handled?
      </h1>
      <div style={{ fontSize: 13.5, color: "var(--muted)", marginTop: 6, maxWidth: 580 }}>
        Your feedback teaches the system. Less noise, sharper escalations next time.
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 14, alignItems: "center" }}>
        <EnvPill env={a.env}/>
        <NsPill ns={a.namespace}/>
        <CompPill c={a.component}/>
        <span style={{ color: "var(--muted-2)", margin: "0 4px" }}>·</span>
        <span style={{ fontSize: 13, color: "var(--text-soft)" }}>{a.alertPlain}</span>
        <VerdictPill v={a.verdict}/>
      </div>
    </div>
  );
}

function FeedbackForm({ filled = false, submitted = false }) {
  const a = window.CIRES_ALERT || (window.CIRES_ALERTS && window.CIRES_ALERTS[0]) || {};
  const [theme] = window.useTheme();
  const [useful, setUseful] = useFb(filled ? "yes" : null);
  const [verdict, setVerdict] = useFb(filled ? "yes" : null);
  const [action, setAction] = useFb(filled ? "partial" : null);
  const [cause, setCause] = useFb(filled ? "Spring-boot JDBC pool — DB write latency from a slow ALTER TABLE we missed." : "");
  const [tags, setTags] = useFb(filled ? new Set(["real-incident", "good-catch"]) : new Set());
  const [notes, setNotes] = useFb(filled
    ? "Action was right direction but I scaled spring-boot to 8 not 6. Worth checking why the LLM picked 6."
    : "");
  // SF-7 (2026-05-23): submit state + error state, swap to confirmation on success.
  const [isSubmitted, setIsSubmitted] = useFb(submitted);
  const [submitErr, setSubmitErr] = useFb(null);
  const [busy, setBusy] = useFb(false);

  const toggleTag = (v) => {
    const next = new Set(tags);
    next.has(v) ? next.delete(v) : next.add(v);
    setTags(next);
  };

  // POST /feedback/rate/{short_id} via the helper injected by the
  // server-rendered page (window.cires_submit_rating).
  const onSave = async () => {
    if (busy) return;
    setBusy(true); setSubmitErr(null);
    const payload = {
      rating: useful,
      verdict_was_right: verdict,
      action_was_right: action,
      actual_cause: cause || null,
      tags: Array.from(tags),
      notes: notes || null,
      rater: "operator", // SF-7 placeholder; real session-bound rater in Sprint 5
    };
    try {
      if (typeof window.cires_submit_rating !== "function") {
        // Local/canvas preview without backend — just simulate
        await new Promise(r => setTimeout(r, 200));
      } else {
        await window.cires_submit_rating(payload);
      }
      setIsSubmitted(true);
    } catch (e) {
      setSubmitErr(String(e && e.message ? e.message : e));
    } finally {
      setBusy(false);
    }
  };

  if (isSubmitted || submitted) {
    return (
      <div className="cires" data-theme={theme} style={{ background: "var(--bg)", minHeight: "100%", padding: 24 }}>
        <div className="card" style={{
          maxWidth: 720, margin: "60px auto", padding: "44px 36px", textAlign: "center",
        }}>
          <div style={{
            width: 60, height: 60, borderRadius: "50%",
            background: "rgba(107,207,127,.14)",
            border: "1px solid rgba(107,207,127,.45)",
            display: "grid", placeItems: "center", margin: "0 auto 18px",
            color: "var(--accent-green)",
          }}>
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m5 12 5 5L20 7"/></svg>
          </div>
          <div style={{ fontSize: 20, fontWeight: 600, marginBottom: 10 }}>Thanks</div>
          <div style={{ fontSize: 14, color: "var(--text-soft)", maxWidth: 460, margin: "0 auto", lineHeight: 1.55 }}>
            This feedback is wired into the <span style={{ color: "var(--accent-cyan)" }}>suppression cache</span> and the <span style={{ color: "var(--accent-purple)" }}>exemplar library</span>. Future fires of this fingerprint will use it.
          </div>
          {/* 2026-06-04 (WS-2 F-005): was two dead <button>s, which
              trapped the operator on the confirmation screen after
              submit. Anchors so middle-click + cmd-click work. The
              detail href reads window.CIRES_RATE_SHORT_ID injected
              by the /rate route handler. */}
          <div style={{ display: "flex", gap: 10, justifyContent: "center", marginTop: 24 }}>
            <a className="btn primary" href="/dashboard"
               style={{ textDecoration: "none" }}>Back to dashboard</a>
            <a className="btn ghost"
               href={`/dashboard/alert/${(typeof window !== "undefined" && window.CIRES_RATE_SHORT_ID) || a.id}`}
               style={{ color: "var(--muted)", textDecoration: "none" }}>View this alert's detail</a>
          </div>
          <div style={{
            marginTop: 26, paddingTop: 18, borderTop: "1px solid var(--border)",
            fontSize: 11.5, color: "var(--muted)",
          }}>
            Fingerprint <span className="mono" style={{ color: "var(--text-soft)" }}>{a.fingerprint}</span> · feedback saved at 16:51:08 UTC
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="cires" data-theme={theme} style={{ background: "var(--bg)", minHeight: "100%" }}>
      <div className="card" style={{ maxWidth: 720, margin: "30px auto", overflow: "hidden", borderRadius: 14 }}>
        <FeedbackHeader a={a}/>
        <div style={{ padding: "24px 28px" }}>
          <RadioGroup question="Was this useful?" options={YN_OPTS} value={useful} onChange={setUseful}/>
          <RadioGroup question="Was the verdict right?" hint={`verdict was ${a.verdict}`} options={YN_OPTS_3} value={verdict} onChange={setVerdict}/>
          <RadioGroup question="Was the suggested action right?" options={YN_OPTS_4} value={action} onChange={setAction}/>

          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 14.5, fontWeight: 500, marginBottom: 8 }}>
              What was the actual cause?
              <span style={{ fontSize: 12, color: "var(--muted-2)", marginLeft: 8, fontWeight: 400 }}>optional</span>
            </div>
            <input className="input" value={cause} onChange={(e)=>setCause(e.target.value)}
                   placeholder="e.g. real cause was X on Y" style={{ width: "100%", padding: "10px 12px", fontSize: 13.5 }}/>
          </div>

          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 14.5, fontWeight: 500, marginBottom: 10 }}>Tags</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 7 }}>
              {TAG_OPTIONS.map(t => (
                <TagChip key={t.v} active={tags.has(t.v)} color={t.color} label={t.label} onClick={() => toggleTag(t.v)}/>
              ))}
            </div>
          </div>

          <div style={{ marginBottom: 22 }}>
            <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", marginBottom: 8 }}>
              <div style={{ fontSize: 14.5, fontWeight: 500 }}>
                Notes <span style={{ fontSize: 12, color: "var(--muted-2)", marginLeft: 6, fontWeight: 400 }}>optional · 280 chars</span>
              </div>
              <div style={{ fontSize: 11.5, color: "var(--muted-2)" }}>{notes.length}/280</div>
            </div>
            <textarea className="input" value={notes} onChange={(e)=>setNotes(e.target.value)} maxLength={280}
              placeholder="What did you actually do? Anything the model missed?"
              style={{ width: "100%", minHeight: 88, padding: 12, fontSize: 13.5, fontFamily: "inherit", resize: "vertical" }}/>
          </div>

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div style={{ fontSize: 12, color: "var(--muted)" }}>
              Submitted feedback is anonymous to the team but tagged to <span style={{ color: "var(--text-soft)" }}>y.benhaddou</span> for audit.
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              {submitErr && <span style={{ color: "var(--accent-red)", fontSize: 12 }}>Save failed: {submitErr}</span>}
              <button className="btn ghost" style={{ color: "var(--muted)" }} onClick={() => window.history.back()}>Cancel</button>
              <button className="btn primary" onClick={onSave} disabled={busy} style={{ opacity: busy ? 0.6 : 1, cursor: busy ? "default" : "pointer" }}>
                {busy ? "Saving…" : "Save feedback"}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function FeedbackEmpty()    { return <FeedbackForm/>; }
function FeedbackFilling()  { return <FeedbackForm filled/>; }
function FeedbackSubmitted(){ return <FeedbackForm submitted/>; }

Object.assign(window, { FeedbackEmpty, FeedbackFilling, FeedbackSubmitted });
