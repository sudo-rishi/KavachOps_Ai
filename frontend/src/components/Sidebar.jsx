import { useState } from "react";

const NAV_ITEMS = [
  { id:"dashboard",  icon:"⬡", label:"Dashboard",      badge:null,      badgeColor:"red"    },
  { id:"network",    icon:"📡", label:"Network & IDS",  badge:"alerts",  badgeColor:"red"    },
  { id:"events",     icon:"🪟", label:"Win Events",     badge:"events",  badgeColor:"amber"  },
  { id:"malware",    icon:"🦠", label:"Malware",        badge:"malware", badgeColor:"red"    },
  { id:"incidents",  icon:"🔥", label:"Incidents",      badge:"incidents",badgeColor:"amber" },
  { id:"vuln",       icon:"🔍", label:"Vulnerability",  badge:null,      badgeColor:null     },
  { id:"honeypot",   icon:"🍯", label:"Honeypots",      badge:null,      badgeColor:null     },
  { id:"reports",    icon:"📊", label:"Reports",        badge:null,      badgeColor:null     },
  { id:"settings",   icon:"⚙️", label:"Settings",       badge:null,      badgeColor:null     },
];

const BADGE_COLORS = {
  red:   { bg:"#fff1f2", text:"#be123c", border:"#fecdd3" },
  amber: { bg:"#fffbeb", text:"#b45309", border:"#fde68a" },
  blue:  { bg:"#f0f5ff", text:"#1340b8", border:"#c1d4ff" },
  green: { bg:"#ecfdf5", text:"#047857", border:"#a7f3d0" },
};

const MODULE_ICON_COLORS = {
  dashboard: "#2563eb", network: "#0f766e", events: "#0891b2", malware: "#16a34a",
  incidents: "#e11d48", vuln: "#d97706", honeypot: "#9333ea", reports: "#0891b2", settings: "#64748b",
};

function ModuleIcon({ id }) {
  const color = MODULE_ICON_COLORS[id] || "#64748b";
  const paths = {
    dashboard: <><path d="M12 3 20 7v5c0 4.5-3.1 7.6-8 9-4.9-1.4-8-4.5-8-9V7l8-4Z" /><path d="m9 12 2 2 4-4" /></>,
    network: <><circle cx="6" cy="12" r="2" /><circle cx="18" cy="7" r="2" /><circle cx="18" cy="17" r="2" /><path d="m8 11 8-3M8 13l8 3" /></>,
    events: <><rect x="4" y="4" width="16" height="16" rx="2" /><path d="M8 8h8M8 12h8M8 16h5" /></>,
    malware: <><path d="M9 8V5M15 8V5M7 11H4M20 11h-3M8 16l-2 3M16 16l2 3" /><path d="M8 8h8a3 3 0 0 1 3 3v3a5 5 0 0 1-10 0v-3a3 3 0 0 1 3-3Z" /></>,
    incidents: <><path d="M12 3c1.8 3.2 5 5.1 5 9a5 5 0 0 1-10 0c0-2 1-3.7 2.6-5.2" /><path d="M12 12c1.3 1.1 1.8 2.1 1.8 3a1.8 1.8 0 0 1-3.6 0c0-.9.5-1.8 1.8-3Z" /></>,
    vuln: <><circle cx="10.5" cy="10.5" r="6" /><path d="m15 15 5 5M10.5 7.5v6M7.5 10.5h6" /></>,
    honeypot: <><path d="M8 4h8M9 4v4l-3 7a3 3 0 0 0 3 4h6a3 3 0 0 0 3-4l-3-7V4" /><path d="M8 14h8" /></>,
    reports: <><path d="M5 20V10M12 20V4M19 20v-7" /><path d="M3 20h18" /></>,
    settings: <><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-1.4 1.4-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-2v-.2a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L9 17l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.6-1H7v-2h.2a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L8.4 9 9.8 7.6l.1.1a1.7 1.7 0 0 0 1.9.3 1.7 1.7 0 0 0 1-1.6v-.2h2v.2a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.2 9l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v2h-.2a1.7 1.7 0 0 0-1 1Z" /></>,
  };
  return <svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[id]}</svg>;
}

export default function Sidebar({ activePage, onNavigate, badges = {}, status = {} }) {
  const [hovId, setHovId] = useState(null);

  return (
    <aside style={{
      width: "var(--sidebar-w)", minWidth: "var(--sidebar-w)",
      height: "100vh", background: "#ffffff",
      borderRight: "1.5px solid var(--color-border)",
      display: "flex", flexDirection: "column",
      boxShadow: "2px 0 8px rgba(15,23,42,0.04)",
      position: "sticky", top: 0, zIndex: 100,
    }}>
      {/* Logo */}
      <div style={{
        padding: "26px 18px 12px",
        borderBottom: "1.5px solid var(--color-border)",
        display: "flex", alignItems: "center", gap: 12,
      }}>
        <div style={{
          width: 46, height: 46, borderRadius: 14,
          background: "#ffffff", overflow: "hidden",
          display: "flex", alignItems: "center", justifyContent: "center",
          fontSize: 20, flexShrink: 0,
          boxShadow: "0 4px 12px rgba(45,107,255,0.25)",
        }}>
          <img
            src="/kavachops-logo.png"
            alt="KavachOps AI logo"
            style={{
              width: "100%", height: "100%", objectFit: "contain",
              transform: "none",
            }}
          />
        </div>
        <div>
          <div style={{ fontFamily:"var(--font-display)", fontWeight:800, fontSize:16,
            background:"linear-gradient(135deg, #0f2b5f 0%, #0f766e 100%)",
            WebkitBackgroundClip:"text", WebkitTextFillColor:"transparent",
            letterSpacing:"-0.02em" }}>
            KavachOps AI
          </div>
          <div style={{ fontFamily:"var(--font-mono)", fontSize:10, fontWeight:800,
            background:"linear-gradient(90deg, #0284c7 0%, #0f9f9a 100%)",
            WebkitBackgroundClip:"text", WebkitTextFillColor:"transparent",
            letterSpacing:"0.04em" }}>
            Sarvam Sarva Raksha
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav style={{ flex:1, overflowY:"auto", padding:"10px 10px 0" }}>
        <div style={{ fontFamily:"var(--font-mono)", fontSize:9, color:"var(--color-text-tertiary)",
          letterSpacing:"0.1em", textTransform:"uppercase", padding:"8px 8px 4px",
          fontWeight:600 }}>Modules</div>

        {NAV_ITEMS.map(item => {
          const isActive = activePage === item.id;
          const isHov    = hovId === item.id;
          const badgeVal = item.badge ? badges[item.badge] : null;
          const bc       = item.badgeColor ? BADGE_COLORS[item.badgeColor] : null;

          return (
            <div
              key={item.id}
              onClick={() => onNavigate(item.id)}
              onMouseEnter={() => setHovId(item.id)}
              onMouseLeave={() => setHovId(null)}
              style={{
                display:"flex", alignItems:"center", gap:9, padding:"8px 10px",
                borderRadius:"var(--r-md)", cursor:"pointer", marginBottom:1,
                transition:"all 0.13s",
                background: isActive ? "#f0f5ff" : isHov ? "#f8fafc" : "transparent",
                borderLeft: isActive ? "2.5px solid #2d6bff" : "2.5px solid transparent",
              }}
            >
              <span style={{ width:20, height:20, display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0 }}>
                <ModuleIcon id={item.id} />
              </span>
              <span style={{
                fontFamily:"var(--font-body)", fontWeight:isActive ? 600 : 500, fontSize:13,
                color: isActive ? "#1340b8" : "var(--color-text-secondary)", flex:1,
              }}>{item.label}</span>
              {badgeVal > 0 && bc && (
                <span style={{
                  background:bc.bg, color:bc.text, border:`1px solid ${bc.border}`,
                  fontSize:10, fontFamily:"var(--font-mono)", fontWeight:700,
                  padding:"1px 6px", borderRadius:99, minWidth:18, textAlign:"center",
                }}>{badgeVal}</span>
              )}
            </div>
          );
        })}
      </nav>

      {/* System Status */}
      <div style={{
        padding:"14px 14px 16px",
        borderTop:"1.5px solid var(--color-border)",
        background:"#fafbfd",
      }}>
        <div style={{ fontFamily:"var(--font-mono)", fontSize:9, color:"var(--color-text-tertiary)",
          letterSpacing:"0.1em", textTransform:"uppercase", marginBottom:8, fontWeight:600 }}>
          System Status
        </div>
        {[
          { label:"Capture",  val: status.capture  ? "Active"    : "Inactive",  ok: status.capture  },
          { label:"Win-Evts", val: "Polling",                                   ok: true            },
          { label:"ML Svc",   val: "Online",                                    ok: true            },
          { label:"Sarvam AI",val: "Connected",                                 ok: true            },
          { label:"Database", val: "Connected",                                 ok: true            },
        ].map(s => (
          <div key={s.label} style={{ display:"flex", justifyContent:"space-between",
            alignItems:"center", marginBottom:5 }}>
            <span style={{ fontFamily:"var(--font-mono)", fontSize:10,
              color:"var(--color-text-tertiary)" }}>{s.label}</span>
            <div style={{ display:"flex", alignItems:"center", gap:5 }}>
              <span style={{
                width:6, height:6, borderRadius:"50%",
                background: s.ok ? "#10b981" : "#94a3b8",
                display:"inline-block",
                animation: s.ok ? "pulseDot 2.5s ease-in-out infinite" : "none",
              }} />
              <span style={{ fontFamily:"var(--font-mono)", fontSize:10,
                color: s.ok ? "#047857" : "var(--color-text-tertiary)",
                fontWeight:600 }}>{s.val}</span>
            </div>
          </div>
        ))}
      </div>
    </aside>
  );
}
