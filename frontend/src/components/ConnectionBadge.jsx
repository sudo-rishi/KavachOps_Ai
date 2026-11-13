import { useState } from "react";

export function ConnectionBadge({ wsStatus, mlOnline, captureRunning }) {
  const [open, setOpen] = useState(false);

  const wsOk   = wsStatus === "connected";
  const wsIcon = { connected:"🟢", connecting:"🟡", disconnected:"🔴", failed:"🔴" }[wsStatus] || "🔴";

  return (
    <div style={{ position:"relative" }}>
      <button
        onClick={() => setOpen(p => !p)}
        style={{
          display:"flex", alignItems:"center", gap:7, padding:"4px 11px",
          borderRadius:99, cursor:"pointer", border:"1.5px solid",
          fontFamily:"var(--font-mono)", fontSize:10, fontWeight:700,
          background: wsOk ? "#ecfdf5" : "#fff1f2",
          borderColor: wsOk ? "#a7f3d0" : "#fecdd3",
          color: wsOk ? "#047857" : "#be123c",
          transition:"all 0.15s",
        }}
      >
        <span style={{
          width:6, height:6, borderRadius:"50%",
          background: wsOk ? "#10b981" : "#f43f5e",
          display:"inline-block",
          animation: wsOk ? "pulseDot 2s ease-in-out infinite" : "none",
        }}/>
        {wsOk ? "LIVE" : wsStatus.toUpperCase()}
      </button>

      {open && (
        <div style={{
          position:"absolute", top:"calc(100% + 8px)", right:0, zIndex:300,
          background:"#fff", border:"1.5px solid var(--color-border)",
          borderRadius:"var(--r-lg)", boxShadow:"var(--shadow-lg)",
          width:260, animation:"fadeUp .18s ease",
          padding:0, overflow:"hidden",
        }}>
          <div style={{ padding:"12px 16px", borderBottom:"1.5px solid var(--color-border)", background:"#fafbfd" }}>
            <div style={{ fontFamily:"var(--font-display)", fontWeight:700, fontSize:13, color:"var(--color-text-primary)" }}>
              Connection Status
            </div>
          </div>
          <div style={{ padding:"12px 16px" }}>
            {[
              { label:"WebSocket",  value: wsStatus,              ok: wsOk,           hint:"STOMP / SockJS" },
              { label:"ML Service", value: mlOnline ? "Online" : "Offline", ok: mlOnline, hint:"localhost:5000" },
              { label:"Capture",    value: captureRunning ? "Active" : "Idle", ok: captureRunning, hint:"Npcap / Pcap4J" },
            ].map(row => (
              <div key={row.label} style={{
                display:"flex", alignItems:"center", justifyContent:"space-between",
                padding:"7px 0", borderBottom:"1px solid #f1f5f9",
              }}>
                <div>
                  <div style={{ fontSize:12, fontWeight:600, color:"var(--color-text-primary)" }}>{row.label}</div>
                  <div style={{ fontSize:10, fontFamily:"var(--font-mono)", color:"var(--color-text-tertiary)" }}>{row.hint}</div>
                </div>
                <span style={{
                  fontFamily:"var(--font-mono)", fontSize:10, fontWeight:700,
                  padding:"2px 8px", borderRadius:99,
                  background: row.ok ? "#ecfdf5" : "#f1f5f9",
                  color:       row.ok ? "#047857" : "#64748b",
                  border:`1.5px solid ${row.ok ? "#a7f3d0" : "#e2e8f0"}`,
                  textTransform:"uppercase",
                }}>{row.value}</span>
              </div>
            ))}
          </div>
          <button onClick={() => setOpen(false)} style={{
            width:"100%", padding:"9px 0", background:"none", border:"none",
            borderTop:"1.5px solid var(--color-border)", cursor:"pointer",
            fontFamily:"var(--font-mono)", fontSize:11, color:"var(--color-text-tertiary)",
          }}>Close</button>
        </div>
      )}

      {/* Click-outside close */}
      {open && (
        <div style={{ position:"fixed", inset:0, zIndex:299 }} onClick={() => setOpen(false)} />
      )}
    </div>
  );
}
