import { useState, useEffect } from "react";
import { Btn, LivePulse } from "./UI.jsx";
import { fmtTime } from "../utils/dateFormatter.js";

const PAGE_META = {
  dashboard: { title:"Dashboard",           path:["Overview", "Command Centre"]        },
  network:   { title:"Network & IDS",        path:["Module 3", "Capture", "Alerts"]     },
  events:    { title:"Windows Events",       path:["Module 3B", "Win Events", "Log"]    },
  malware:   { title:"Malware Detection",    path:["Module 5", "Scan", "Quarantine"]    },
  incidents: { title:"Incident Management", path:["Module 6", "Incidents", "Timeline"] },
  vuln:      { title:"Vulnerability",        path:["Module 4", "Scanner", "Findings"]   },
  honeypot:  { title:"Honeypots",            path:["Module 7", "Traps", "Profiles"]     },
  reports:   { title:"Reports",              path:["Module 8", "Reports", "Templates"]  },
  settings:  { title:"Settings",             path:["Module 9", "System", "Control"]     },
};

export default function Header({ page, user, captureRunning, onToggleCapture, onLogout, onToast, extra }) {
  const [clock, setClock] = useState(new Date());

  useEffect(() => {
    const t = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const meta = PAGE_META[page] || PAGE_META.dashboard;

  return (
    <header style={{
      height: "var(--header-h)", background: "#ffffff",
      borderBottom: "1.5px solid var(--color-border)",
      display: "flex", alignItems: "center", padding: "0 22px",
      gap: 16, position: "sticky", top: 0, zIndex: 90,
      boxShadow: "0 1px 4px rgba(15,23,42,0.04)",
    }}>
      {/* Page title + breadcrumb */}
      <div>
        <h1 style={{
          fontFamily: "var(--font-display)", fontWeight: 700, fontSize: 15,
          color: "var(--color-text-primary)", letterSpacing: "-0.02em", lineHeight: 1.2,
        }}>{meta.title}</h1>
        <div style={{ display:"flex", gap:5, alignItems:"center" }}>
          {meta.path.map((p, i) => (
            <span key={i} style={{ display:"flex", alignItems:"center", gap:5 }}>
              {i > 0 && <span style={{ color:"#cbd5e1", fontSize:10 }}>›</span>}
              <span style={{ fontFamily:"var(--font-mono)", fontSize:10,
                color: i === meta.path.length - 1 ? "var(--color-text-secondary)" : "var(--color-text-tertiary)" }}>
                {p}
              </span>
            </span>
          ))}
        </div>
      </div>

      <div style={{ flex:1 }} />

      {/* Connection badge slot */}
      {extra && <div>{extra}</div>}

      {/* Live indicator */}
      <LivePulse active={captureRunning} label={captureRunning ? "CAPTURING" : "IDLE"} />

      {/* Clock */}
      <div style={{
        fontFamily: "var(--font-mono)", fontSize: 13, fontWeight: 500,
        color: "#1340b8", background: "#f0f5ff", padding: "5px 12px",
        borderRadius: "var(--r-md)", border: "1px solid #c1d4ff",
        letterSpacing: "0.04em",
      }}>
        {fmtTime(clock)}
      </div>

      {/* Capture toggle */}
      <Btn
        variant={captureRunning ? "danger" : "success"}
        size="sm"
        onClick={onToggleCapture}
      >
        {captureRunning ? "⏹ Stop Capture" : "▶ Start Capture"}
      </Btn>

      {/* Refresh */}
      <Btn variant="ghost" size="sm"
        onClick={() => onToast("Data refreshed", "success")}>
        ⟳ Refresh
      </Btn>

      {/* User + logout */}
      <div style={{ display:"flex", alignItems:"center", gap:8 }}>
        <div style={{
          width:30, height:30, borderRadius:"50%",
          background:"linear-gradient(135deg, #2d6bff 0%, #7c3aed 100%)",
          display:"flex", alignItems:"center", justifyContent:"center",
          fontSize:12, fontWeight:700, color:"#fff",
          fontFamily:"var(--font-display)",
        }}>{(user?.username || "A").charAt(0).toUpperCase()}</div>
        <div style={{ lineHeight:1.2 }}>
          <div style={{ fontSize:12, fontWeight:600, color:"var(--color-text-primary)" }}>{user?.username}</div>
          <div style={{ fontSize:10, fontFamily:"var(--font-mono)", color:"var(--color-text-tertiary)",
            textTransform:"uppercase", letterSpacing:"0.05em" }}>{user?.role}</div>
        </div>
        <Btn variant="ghost" size="xs" onClick={onLogout}>⏻</Btn>
      </div>
    </header>
  );
}
