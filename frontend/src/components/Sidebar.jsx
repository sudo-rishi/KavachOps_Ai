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
              <span style={{ fontSize:14, width:20, textAlign:"center", flexShrink:0 }}>{item.icon}</span>
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
