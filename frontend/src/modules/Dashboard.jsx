import { useMemo, useState } from "react";
import { StatCard, Panel, Grid, Badge, IPPill, FeedItem, ProgressBar, LivePulse, EmptyState, Select } from "../components/UI.jsx";
import { fmtTime } from "../utils/dateFormatter.js";
function fmtNum(n) {
  return n >= 1000000 ? (n/1000000).toFixed(1)+"M" : n >= 1000 ? (n/1000).toFixed(1)+"K" : String(n);
}

const TIME_RANGE_OPTIONS = [
  { value: "1h",  label: "Last 1 hour" },
  { value: "24h", label: "Last 24 hours" },
  { value: "30d", label: "Last 30 days" },
];

const TIME_RANGE_MS = {
  "1h":  60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
  "30d": 30 * 24 * 60 * 60 * 1000,
};

function parseTs(value) {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

function filterByWindow(list, pickTimestamp, nowMs, windowMs) {
  return list.filter((item) => {
    const ts = parseTs(pickTimestamp(item));
    if (!ts) return false;
    return nowMs - ts.getTime() <= windowMs;
  });
}

function miniTrendPoints(values, w = 440, h = 110, pad = 14) {
  if (!values.length) return "";
  const max = Math.max(...values, 1);
  const step = values.length > 1 ? (w - pad * 2) / (values.length - 1) : 0;
  return values.map((v, i) => {
    const x = pad + i * step;
    const y = h - pad - ((v / max) * (h - pad * 2));
    return `${x},${y}`;
  }).join(" ");
}

function areaPath(points, h = 110, pad = 14) {
  if (!points.length) return "";
  const first = points[0].split(",");
  const last = points[points.length - 1].split(",");
  return `M ${first[0]} ${h - pad} L ${points.join(" L ")} L ${last[0]} ${h - pad} Z`;
}

function ModuleLogo({ type, color }) {
  const common = {
    width: 22, height: 22, viewBox: "0 0 24 24", fill: "none",
    stroke: color, strokeWidth: 1.8, strokeLinecap: "round", strokeLinejoin: "round",
    "aria-hidden": true,
  };
  if (type === "network") return <svg {...common}><circle cx="5" cy="12" r="2.4" fill={`${color}22`} /><circle cx="18.5" cy="6" r="2.4" fill={`${color}22`} /><circle cx="18.5" cy="18" r="2.4" fill={`${color}22`} /><path d="m7.2 11 9-4M7.2 13l9 4" /></svg>;
  if (type === "events") return <svg {...common}><rect x="3.5" y="4" width="17" height="16" rx="2.5" fill={`${color}12`} /><path d="M8 4v16M16 4v16M3.5 12h17" /><path d="M6 7h.01M11 7h.01M19 7h.01M6 16h.01M11 16h.01M19 16h.01" strokeWidth="2.4" /></svg>;
  if (type === "malware") return <svg {...common}><path d="M8 8.5a4 4 0 0 1 8 0v7a4 4 0 0 1-8 0z" fill={`${color}16`} /><path d="M6 10h-2M6 14H3M18 10h2M18 14h3M9 5 8 3M15 5l1-2M9 19l-1 2M15 19l1 2" /><path d="M9.5 12h.01M14.5 12h.01M10 16c1.2.7 2.8.7 4 0" strokeWidth="2.2" /></svg>;
  if (type === "vuln") return <svg {...common}><circle cx="10.5" cy="10.5" r="6" fill={`${color}12`} /><path d="m15 15 5 5M10.5 7.5v6M7.5 10.5h6" /></svg>;
  if (type === "honeypot") return <svg {...common}><path d="M8 4h8M9 4v4l-3 7a3 3 0 0 0 3 4h6a3 3 0 0 0 3-4l-3-7V4" fill={`${color}12`} /><path d="M8 14h8" /></svg>;
  return <svg {...common}><rect x="5" y="6" width="14" height="13" rx="3" fill={`${color}16`} /><path d="M9 3v3M15 3v3M3 11h2M19 11h2M9 19v2M15 19v2" /><circle cx="9.5" cy="12" r="1" fill={color} stroke="none" /><circle cx="14.5" cy="12" r="1" fill={color} stroke="none" /><path d="M9 15h6" /></svg>;
}

function moduleAccent(label, fallback) {
  if (label === "Vuln Scanner") return "#d97706";
  if (label === "Honeypots") return "#0f766e";
  return fallback;
}

export default function Dashboard({ appState, onNavigate }) {
  const {
    alerts,
    incidents,
    malwareScans,
    winEvents,
    honeypots,
    idsRules,
    vulnFindings,
    capturePackets,
    captureRunning,
    captureLoops,
    captureRestarts,
    feedItems,
    trafficFeed,
  } = appState;

  const [timeRange, setTimeRange] = useState("24h");

  const nowMs = Date.now();
  const selectedWindowMs = TIME_RANGE_MS[timeRange] || TIME_RANGE_MS["24h"];
  const selectedRangeLabel = TIME_RANGE_OPTIONS.find(o => o.value === timeRange)?.label || "Last 24 hours";

  const alertsInWindow = useMemo(
    () => filterByWindow(alerts, (a) => a.timestamp, nowMs, selectedWindowMs),
    [alerts, nowMs, selectedWindowMs]
  );
  const incidentsInWindow = useMemo(
    () => filterByWindow(incidents, (i) => i.createdAt, nowMs, selectedWindowMs),
    [incidents, nowMs, selectedWindowMs]
  );
  const malwareInWindow = useMemo(
    () => filterByWindow(malwareScans, (m) => m.scanTime, nowMs, selectedWindowMs),
    [malwareScans, nowMs, selectedWindowMs]
  );
  const eventsInWindow = useMemo(
    () => filterByWindow(winEvents, (e) => e.eventTime, nowMs, selectedWindowMs),
    [winEvents, nowMs, selectedWindowMs]
  );

  const critAlerts  = alertsInWindow.filter(a => a.severity === "CRITICAL").length;
  const highAlerts  = alertsInWindow.filter(a => a.severity === "HIGH").length;
  const medAlerts   = alertsInWindow.filter(a => a.severity === "MEDIUM").length;
  const lowAlerts   = alertsInWindow.filter(a => a.severity === "LOW").length;
  const openInc     = incidentsInWindow.filter(i => ["open","investigating"].includes(i.status)).length;
  const secEvts     = eventsInWindow.filter(e => e.securityRelevant).length;
  const infected    = malwareInWindow.filter(s => s.scanResult === "infected").length;
  const totalAlerts = critAlerts + highAlerts + medAlerts + lowAlerts || 1;
  const activeHPs   = honeypots.filter(h => h.active).length;
  const openVulns   = vulnFindings.filter(f => f.status === "open").length;
  const activeRules = idsRules.filter(r => r.active).length;

  const moduleStatus = [
    { icon:"📡", label:"Network IDS",    status:"Active",    color:"#10b981", sub:`${activeRules} rules`, page:"network"   },
    { icon:"🪟", label:"Win Events",     status:"Polling",   color:"#0ea5e9", sub:"Every 5s",             page:"events"    },
    { icon:"🦠", label:"Malware Engine", status:"Ready",     color:"#10b981", sub:"YARA + VT",            page:"malware"   },
    { icon:"🔍", label:"Vuln Scanner",   status: openVulns > 0 ? "Findings" : "Idle", color: openVulns > 0 ? "#f59e0b" : "#94a3b8", sub:`${openVulns} open`, page:"vuln" },
    { icon:"🍯", label:"Honeypots",      status: activeHPs > 0 ? `${activeHPs} Active` : "Inactive", color: activeHPs > 0 ? "#10b981" : "#94a3b8", sub:"Attacker traps", page:"honeypot" },
    { icon:"🤖", label:"ML Service",     status:"Online",    color:"#7c3aed", sub:"Anomaly detect",       page:"network"   },
  ];

  const severityCounts = [critAlerts, highAlerts, medAlerts, lowAlerts];
  const severityTotal = Math.max(1, severityCounts.reduce((a, b) => a + b, 0));
  const sevPct = severityCounts.map(v => (v / severityTotal) * 100);
  const trendRaw = alertsInWindow.slice(0, 24);
  const trendBuckets = new Array(12).fill(0);
  trendRaw.forEach((_, idx) => {
    trendBuckets[idx % 12] += 1;
  });
  const trendPolyline = miniTrendPoints(trendBuckets);
  const trendArea = areaPath(trendPolyline ? trendPolyline.split(" ") : []);

  return (
    <div className="page-enter">
      <div style={{ display:"flex", justifyContent:"flex-end", marginBottom:12 }}>
        <Select
          value={timeRange}
          onChange={setTimeRange}
          options={TIME_RANGE_OPTIONS}
          style={{ minWidth: 160 }}
        />
      </div>

      {/* Top stats */}
      <Grid cols={4} gap={16} style={{ marginBottom:20 }}>
        <StatCard icon="🚨" label="Active Alerts"    value={critAlerts + highAlerts}
          sub={`${selectedRangeLabel} · Critical + High`} color="#e11d48" trend={12} onClick={() => onNavigate("network")} />
        <StatCard icon="🔥" label="Open Incidents"   value={openInc}
          sub={selectedRangeLabel} color="#f59e0b" onClick={() => onNavigate("incidents")} />
        <StatCard icon="📦" label="Packets Captured" value={fmtNum(capturePackets)}
          sub="This session" color="#2d6bff" onClick={() => onNavigate("network")} />
        <StatCard icon="🪟" label="Security Events"  value={secEvts}
          sub={selectedRangeLabel} color="#7c3aed" onClick={() => onNavigate("events")} />
      </Grid>

      <Grid cols={2} gap={16} style={{ marginBottom:20 }}>
        <Panel accent="#2d6bff" title="Traffic Trend Graph" subtitle={`${selectedRangeLabel} · Last 12 slices`}>
          <div style={{ padding:16 }}>
            <svg viewBox="0 0 440 110" style={{ width:"100%", height:120, display:"block" }}>
              <defs>
                <linearGradient id="trendFill" x1="0" x2="0" y1="0" y2="1">
                  <stop offset="0%" stopColor="#2d6bff" stopOpacity="0.35" />
                  <stop offset="100%" stopColor="#2d6bff" stopOpacity="0.03" />
                </linearGradient>
              </defs>
              {[20, 40, 60, 80].map(y => (
                <line key={y} x1="14" y1={y} x2="426" y2={y} stroke="#e2e8f0" strokeWidth="1" />
              ))}
              {trendArea && <path d={trendArea} fill="url(#trendFill)" />}
              {trendPolyline && <polyline points={trendPolyline} fill="none" stroke="#2d6bff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />}
            </svg>
            <div style={{ display:"grid", gridTemplateColumns:"repeat(5, minmax(0,1fr))", gap:8, marginTop:8 }}>
              <div style={{ background:"#f8fafc", border:"1px solid #e2e8f0", borderRadius:8, padding:"8px 10px" }}>
                <div style={{ fontSize:10, color:"#64748b", fontFamily:"var(--font-mono)", textTransform:"uppercase" }}>Total Flow</div>
                <div style={{ fontSize:14, fontWeight:700, color:"#0f172a" }}>{fmtNum(alertsInWindow.length)}</div>
              </div>
              <div style={{ background:"#f8fafc", border:"1px solid #e2e8f0", borderRadius:8, padding:"8px 10px" }}>
                <div style={{ fontSize:10, color:"#64748b", fontFamily:"var(--font-mono)", textTransform:"uppercase" }}>Peak Slice</div>
                <div style={{ fontSize:14, fontWeight:700, color:"#0f172a" }}>{Math.max(...trendBuckets, 0)}</div>
              </div>
              <div style={{ background:"#f8fafc", border:"1px solid #e2e8f0", borderRadius:8, padding:"8px 10px" }}>
                <div style={{ fontSize:10, color:"#64748b", fontFamily:"var(--font-mono)", textTransform:"uppercase" }}>Capture</div>
                <div style={{ fontSize:14, fontWeight:700, color: captureRunning ? "#059669" : "#64748b" }}>{captureRunning ? "Live" : "Idle"}</div>
              </div>
              <div style={{ background:"#f8fafc", border:"1px solid #e2e8f0", borderRadius:8, padding:"8px 10px" }}>
                <div style={{ fontSize:10, color:"#64748b", fontFamily:"var(--font-mono)", textTransform:"uppercase" }}>Capture Loops</div>
                <div style={{ fontSize:14, fontWeight:700, color:"#0369a1" }}>{fmtNum(captureLoops || 0)}</div>
                <div style={{ fontSize:10, color:"#64748b", marginTop:2 }}>Restarts: {fmtNum(captureRestarts || 0)}</div>
              </div>
              <div style={{ background:"#f8fafc", border:"1px solid #e2e8f0", borderRadius:8, padding:"8px 10px" }}>
                <div style={{ fontSize:10, color:"#64748b", fontFamily:"var(--font-mono)", textTransform:"uppercase" }}>Infected Files</div>
                <div style={{ fontSize:14, fontWeight:700, color:"#b91c1c" }}>{infected}</div>
              </div>
            </div>
          </div>
        </Panel>

        <Panel accent="#7c3aed" title="Severity Ring" subtitle="Current alert composition">
          <div style={{ padding:16, display:"flex", gap:18, alignItems:"center" }}>
            <svg viewBox="0 0 160 160" style={{ width:150, height:150, flexShrink:0 }}>
              <circle cx="80" cy="80" r="52" stroke="#e2e8f0" strokeWidth="20" fill="none" />
              <circle cx="80" cy="80" r="52" stroke="#e11d48" strokeWidth="20" fill="none" strokeDasharray={`${(sevPct[0] / 100) * 327} 327`} transform="rotate(-90 80 80)" strokeLinecap="butt" />
              <circle cx="80" cy="80" r="52" stroke="#f59e0b" strokeWidth="20" fill="none" strokeDasharray={`${(sevPct[1] / 100) * 327} 327`} transform={`rotate(${((sevPct[0] / 100) * 360) - 90} 80 80)`} strokeLinecap="butt" />
              <circle cx="80" cy="80" r="52" stroke="#8b5cf6" strokeWidth="20" fill="none" strokeDasharray={`${(sevPct[2] / 100) * 327} 327`} transform={`rotate(${(((sevPct[0] + sevPct[1]) / 100) * 360) - 90} 80 80)`} strokeLinecap="butt" />
              <circle cx="80" cy="80" r="52" stroke="#10b981" strokeWidth="20" fill="none" strokeDasharray={`${(sevPct[3] / 100) * 327} 327`} transform={`rotate(${(((sevPct[0] + sevPct[1] + sevPct[2]) / 100) * 360) - 90} 80 80)`} strokeLinecap="butt" />
              <circle cx="80" cy="80" r="34" fill="#ffffff" />
              <text x="80" y="76" textAnchor="middle" style={{ fontSize:11, fill:"#64748b", fontFamily:"var(--font-mono)" }}>ALERTS</text>
              <text x="80" y="96" textAnchor="middle" style={{ fontSize:20, fill:"#0f172a", fontWeight:700 }}>{severityTotal}</text>
            </svg>
            <div style={{ flex:1 }}>
              {[
                ["Critical", critAlerts, "#e11d48"],
                ["High", highAlerts, "#f59e0b"],
                ["Medium", medAlerts, "#8b5cf6"],
                ["Low", lowAlerts, "#10b981"],
              ].map(([label, value, color]) => (
                <div key={label} style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:8 }}>
                  <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                    <span style={{ width:8, height:8, borderRadius:"50%", background:color, display:"inline-block" }} />
                    <span style={{ fontSize:12, color:"#334155", fontWeight:500 }}>{label}</span>
                  </div>
                  <span style={{ fontFamily:"var(--font-mono)", fontWeight:700, color }}>{value}</span>
                </div>
              ))}
            </div>
          </div>
        </Panel>
      </Grid>

      <Grid cols={2} gap={16} style={{ marginBottom:20 }}>
        {/* Live Feed */}
        <Panel
          accent="#0f9f9a"
          title="Live Alert Feed"
          subtitle={captureRunning ? "Streaming live" : "Start capture to stream"}
          actions={<LivePulse active={captureRunning} label={captureRunning ? "LIVE" : "IDLE"} />}
        >
          <div style={{ maxHeight:280, overflowY:"auto" }}>
            {feedItems.length === 0 ? (
              <EmptyState icon="📡" title="No alerts yet" sub="Start packet capture to begin monitoring" />
            ) : (
              feedItems.slice(0,20).map((f, i) => (
                <FeedItem key={i} time={f.time} severity={f.severity}
                  badgeLabel={f.label} message={f.message} type="sev" />
              ))
            )}
          </div>
        </Panel>

        {/* Threat Breakdown */}
        <Panel accent="#f59e0b" title="Threat Breakdown" subtitle={selectedRangeLabel}>
          <div style={{ padding:18 }}>
            {[
              { label:"Critical", count:critAlerts, color:"#e11d48", pct:(critAlerts/totalAlerts)*100 },
              { label:"High",     count:highAlerts, color:"#f59e0b", pct:(highAlerts/totalAlerts)*100  },
              { label:"Medium",   count:medAlerts,  color:"#8b5cf6", pct:(medAlerts/totalAlerts)*100   },
              { label:"Low",      count:lowAlerts,  color:"#10b981", pct:(lowAlerts/totalAlerts)*100   },
            ].map(s => (
              <div key={s.label} style={{ marginBottom:14 }}>
                <div style={{ display:"flex", justifyContent:"space-between", marginBottom:5 }}>
                  <span style={{ fontSize:13, color:"var(--color-text-secondary)", fontWeight:500 }}>{s.label}</span>
                  <span style={{ fontFamily:"var(--font-mono)", fontSize:12, fontWeight:700, color:s.color }}>{s.count}</span>
                </div>
                <ProgressBar value={s.pct} max={100} color={s.color} height={5} />
              </div>
            ))}

            <div style={{ marginTop:20, paddingTop:16, borderTop:"1.5px solid var(--color-border)" }}>
              <div style={{ fontSize:11, fontFamily:"var(--font-mono)", color:"var(--color-text-tertiary)",
                textTransform:"uppercase", letterSpacing:"0.06em", marginBottom:10, fontWeight:600 }}>
                Protocol Distribution
              </div>
              <div style={{ display:"flex", alignItems:"flex-end", gap:6, height:48 }}>
                {[
                  { label:"TCP",  pct:72, color:"#2d6bff"  },
                  { label:"UDP",  pct:18, color:"#10b981"  },
                  { label:"ICMP", pct:7,  color:"#f59e0b"  },
                  { label:"Other",pct:3,  color:"#94a3b8"  },
                ].map(p => (
                  <div key={p.label} style={{ flex:1, display:"flex", flexDirection:"column", alignItems:"center", gap:4 }}>
                    <div style={{ width:"100%", background:p.color+"22", borderRadius:4,
                      height: `${p.pct * 0.48}px`, position:"relative", overflow:"hidden",
                      border:`1px solid ${p.color}33`,
                    }}>
                      <div style={{ position:"absolute", bottom:0, left:0, right:0,
                        background:p.color, height:`${p.pct}%`, borderRadius:"3px 3px 0 0", opacity:0.7 }} />
                    </div>
                    <span style={{ fontSize:9, fontFamily:"var(--font-mono)", color:"var(--color-text-tertiary)" }}>{p.label}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </Panel>
      </Grid>

      {/* Module Status Grid */}
      <Grid cols={3} gap={12}>
        {moduleStatus.map((m, i) => (
          <div key={i}
            onClick={() => onNavigate(m.page)}
            style={{
              background:`linear-gradient(135deg, #ffffff 0%, ${moduleAccent(m.label, m.color)}12 100%)`,
              border:`1.5px solid ${moduleAccent(m.label, m.color)}35`,
              borderRadius:"var(--r-lg)", padding:"16px 18px",
              cursor:"pointer", transition:"all 0.15s",
              boxShadow:`0 3px 10px ${moduleAccent(m.label, m.color)}10`,
              position:"relative", overflow:"hidden",
            }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = moduleAccent(m.label, m.color)+"55"; e.currentTarget.style.boxShadow = "var(--shadow-md)"; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = moduleAccent(m.label, m.color)+"35"; e.currentTarget.style.boxShadow = `0 3px 10px ${moduleAccent(m.label, m.color)}10`; }}
          >
            <div style={{ position:"absolute", top:0, left:0, right:0, height:3,
              background:`linear-gradient(90deg, transparent, ${moduleAccent(m.label, m.color)}70, transparent)` }} />
            <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:8 }}>
              <span style={{ width:34, height:34, borderRadius:10, display:"flex",
                alignItems:"center", justifyContent:"center", fontSize:19,
                background:`${moduleAccent(m.label, m.color)}20`, border:`1px solid ${moduleAccent(m.label, m.color)}38`,
                boxShadow:`0 3px 8px ${moduleAccent(m.label, m.color)}12` }}>
                <ModuleLogo type={{
                  "Network IDS": "network",
                  "Win Events": "events",
                  "Malware Engine": "malware",
                  "Vuln Scanner": "vuln",
                  "Honeypots": "honeypot",
                  "ML Service": "ml",
                }[m.label]} color={moduleAccent(m.label, m.color)} />
              </span>
              <div style={{ display:"flex", alignItems:"center", gap:5 }}>
                <span style={{ width:6, height:6, borderRadius:"50%", background:moduleAccent(m.label, m.color),
                  display:"inline-block", animation:"pulseDot 2s ease-in-out infinite" }} />
                <span style={{ fontSize:10, fontFamily:"var(--font-mono)", fontWeight:700,
                  color:moduleAccent(m.label, m.color), textTransform:"uppercase" }}>{m.status}</span>
              </div>
            </div>
            <div style={{ fontFamily:"var(--font-display)", fontWeight:700, fontSize:13,
              color:"var(--color-text-primary)", marginBottom:2 }}>{m.label}</div>
            <div style={{ fontSize:11, color:"var(--color-text-tertiary)" }}>{m.sub}</div>
          </div>
        ))}
      </Grid>

      {/* Recent Alerts Table */}
      {alertsInWindow.length > 0 && (
        <div style={{ marginTop:20 }}>
          <Panel title="Recent Alerts" subtitle="Latest security detections"
            actions={
              <button onClick={() => onNavigate("network")} style={{
                fontFamily:"var(--font-body)", fontSize:12, fontWeight:600,
                color:"#2d6bff", background:"none", border:"none", cursor:"pointer",
              }}>View All →</button>
            }>
            <div style={{ overflowX:"auto" }}>
              <table style={{ width:"100%", borderCollapse:"collapse", fontSize:13 }}>
                <thead>
                  <tr style={{ background:"#fafbfd", borderBottom:"1.5px solid var(--color-border)" }}>
                    {["Time","Severity","Source","Destination","Rule","Status"].map(h => (
                      <th key={h} style={{ textAlign:"left", padding:"10px 14px",
                        fontFamily:"var(--font-mono)", fontSize:10, fontWeight:600,
                        color:"var(--color-text-tertiary)", textTransform:"uppercase", letterSpacing:"0.06em",
                      }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {alertsInWindow.slice(0,5).map(a => (
                    <tr key={a.alertId}
                      style={{ borderBottom:"1px solid #f1f5f9", transition:"background 0.1s" }}
                      onMouseEnter={e => e.currentTarget.style.background = "#f8fafc"}
                      onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                    >
                      <td style={{ padding:"9px 14px", fontFamily:"var(--font-mono)", fontSize:11,
                        color:"var(--color-text-tertiary)", whiteSpace:"nowrap" }}>{fmtTime(a.timestamp)}</td>
                      <td style={{ padding:"9px 14px" }}><Badge severity={a.severity} /></td>
                      <td style={{ padding:"9px 14px" }}><IPPill ip={a.sourceIp} /></td>
                      <td style={{ padding:"9px 14px", fontFamily:"var(--font-mono)", fontSize:11,
                        color:"var(--color-text-secondary)" }}>{a.destinationIp}:{a.destinationPort}</td>
                      <td style={{ padding:"9px 14px", fontSize:12, color:"var(--color-text-secondary)",
                        maxWidth:160, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                        {a.ruleName}</td>
                      <td style={{ padding:"9px 14px" }}><Badge status={a.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        </div>
      )}
    </div>
  );
}
