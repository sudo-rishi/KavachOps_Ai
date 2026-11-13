import { useState, useEffect, useRef } from "react";
import { Panel, Grid, StatCard, Badge, Btn, Modal, FormGroup, DataTable, EmptyState } from "../components/UI.jsx";
import { fmtDateTime } from "../utils/dateFormatter.js";

const HP_TYPE_ICONS = { ssh:"🔐", http:"🌐", ftp:"📁", smtp:"✉", rdp:"🖥", telnet:"⌨" };
const THREAT_COLORS = {
  critical: { bg:"#fff1f2", text:"#be123c", border:"#fecdd3" },
  high:     { bg:"#fffbeb", text:"#b45309", border:"#fde68a" },
  medium:   { bg:"#f5f3ff", text:"#6d28d9", border:"#ddd6fe" },
  low:      { bg:"#ecfdf5", text:"#047857", border:"#a7f3d0" },
};

function RadarViz({ honeypots, attackers }) {
  const canvasRef = useRef(null);
  const angleRef  = useRef(0);
  const rafRef    = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const W = canvas.width, H = canvas.height;
    const cx = W/2, cy = H/2, r = Math.min(W,H)/2 - 20;

    // Fixed attacker positions (deterministic)
    const dots = attackers.map((a, i) => {
      const ang = (i * 2.4 + 0.8) % (Math.PI * 2);
      const d   = r * (0.4 + (i % 3) * 0.2);
      return { x: cx + Math.cos(ang)*d, y: cy + Math.sin(ang)*d, level: a.threatLevel };
    });

    const draw = () => {
      ctx.clearRect(0,0,W,H);
      // Rings
      [r, r*0.66, r*0.33].forEach(rd => {
        ctx.beginPath(); ctx.arc(cx,cy,rd,0,Math.PI*2);
        ctx.strokeStyle = "#e2e8f0"; ctx.lineWidth = 1; ctx.stroke();
      });
      // Cross lines
      ctx.beginPath(); ctx.moveTo(cx,cy-r); ctx.lineTo(cx,cy+r);
      ctx.moveTo(cx-r,cy); ctx.lineTo(cx+r,cy);
      ctx.strokeStyle = "#f1f5f9"; ctx.lineWidth = 1; ctx.stroke();
      // Centre dot
      ctx.beginPath(); ctx.arc(cx,cy,6,0,Math.PI*2);
      ctx.fillStyle = "#2d6bff"; ctx.fill();
      // SOC label
      ctx.fillStyle = "#2d6bff"; ctx.font = "bold 9px 'DM Mono', monospace";
      ctx.textAlign = "center"; ctx.fillText("SOC", cx, cy+16);
      // Sweep
      const a = angleRef.current;
      const grad = ctx.createLinearGradient(cx, cy,
        cx + Math.cos(a)*r, cy + Math.sin(a)*r);
      grad.addColorStop(0, "rgba(45,107,255,0.15)");
      grad.addColorStop(1, "rgba(45,107,255,0)");
      ctx.beginPath();
      ctx.moveTo(cx,cy);
      ctx.arc(cx,cy,r, a - Math.PI/6, a);
      ctx.closePath(); ctx.fillStyle = grad; ctx.fill();
      ctx.beginPath();
      ctx.moveTo(cx,cy);
      ctx.lineTo(cx + Math.cos(a)*r, cy + Math.sin(a)*r);
      ctx.strokeStyle = "rgba(45,107,255,0.7)"; ctx.lineWidth = 1.5; ctx.stroke();
      // Attacker dots
      dots.forEach(d => {
        const tc = THREAT_COLORS[d.level] || THREAT_COLORS.low;
        ctx.beginPath(); ctx.arc(d.x, d.y, 5, 0, Math.PI*2);
        ctx.fillStyle = tc.text; ctx.fill();
        ctx.beginPath(); ctx.arc(d.x, d.y, 8, 0, Math.PI*2);
        ctx.strokeStyle = tc.text+"66"; ctx.lineWidth = 1; ctx.stroke();
      });
      angleRef.current = (a + 0.018) % (Math.PI*2);
      rafRef.current = requestAnimationFrame(draw);
    };
    draw();
    return () => { if (rafRef.current) cancelAnimationFrame(rafRef.current); };
  }, [attackers]);

  return <canvas ref={canvasRef} width={260} height={260} style={{ display:"block", margin:"0 auto" }} />;
}

export default function Honeypot({ appState, onDeployHoneypot, onToggleHoneypot, onToast }) {
  const honeypots = appState.honeypots || [];
  const attackers = appState.attackers || [];
  const stats     = appState.honeypotStats || {};
  const [deployModal, setDeployModal] = useState(false);
  const [newHP, setNewHP] = useState({ name:"", type:"ssh", ip:"", port:"2222" });

  const active       = stats.activeHoneypots ?? honeypots.filter(h => h.active).length;
  const interactions = stats.interactions24h ?? honeypots.reduce((s,h) => s+(h.interactions||0), 0);
  const uniqueAtt    = stats.uniqueAttackers24h ?? attackers.length;
  const critAtt      = attackers.filter(a => a.threatLevel === "critical").length;

  return (
    <div className="page-enter">
      <Grid cols={4} gap={14} style={{ marginBottom:20 }}>
        <StatCard icon="🍯" label="Active Traps"        value={active}       sub="Deployed honeypots"   color="#2d6bff" />
        <StatCard icon="💥" label="Interactions (24h)"  value={interactions} sub="Attacker contacts"    color="#e11d48" />
        <StatCard icon="👤" label="Unique Attackers"     value={uniqueAtt}   sub="Profiled adversaries" color="#f59e0b" />
        <StatCard icon="🎯" label="Critical Threats"    value={critAtt}      sub="High-risk actors"     color="#7c3aed" />
      </Grid>

      <Grid cols={2} gap={16} style={{ marginBottom:20 }}>
        {/* Deployed Honeypots */}
        <Panel title="Deployed Honeypots" subtitle="Active deception infrastructure"
          actions={<Btn size="sm" variant="primary" onClick={() => setDeployModal(true)}>+ Deploy</Btn>}>
          {honeypots.length === 0 ? (
            <EmptyState icon="🍯" title="No honeypots deployed" sub="Deploy traps to lure and profile attackers" />
          ) : (
            honeypots.map(hp => (
              <div key={hp.honeypotId} style={{
                display:"flex", alignItems:"center", justifyContent:"space-between",
                padding:"12px 16px", borderBottom:"1px solid #f1f5f9",
              }}>
                <div style={{ display:"flex", alignItems:"center", gap:12 }}>
                  <div style={{
                    width:38, height:38, borderRadius:"var(--r-md)",
                    background: hp.active ? "#ecfdf5" : "#f1f5f9",
                    border: `1.5px solid ${hp.active ? "#a7f3d0" : "#e2e8f0"}`,
                    display:"flex", alignItems:"center", justifyContent:"center", fontSize:18, flexShrink:0,
                  }}>
                    {HP_TYPE_ICONS[hp.honeypotType] || "🍯"}
                  </div>
                  <div>
                    <div style={{ fontWeight:700, fontSize:13, color:"var(--color-text-primary)" }}>{hp.honeypotName}</div>
                    <div style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--color-text-tertiary)", marginTop:1 }}>
                      {hp.honeypotType.toUpperCase()} · {hp.ipAddress}:{hp.port} · {hp.interactions||0} interactions
                    </div>
                  </div>
                </div>
                <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                  <Badge status={hp.active ? "active" : "inactive"} size="xs" />
                  <Btn size="xs" variant={hp.active ? "ghost" : "success"} onClick={() => {
                    onToggleHoneypot(hp.honeypotId);
                    onToast(hp.honeypotName + (hp.active ? " deactivated" : " activated"), hp.active ? "warning" : "success");
                  }}>{hp.active ? "Disable" : "Enable"}</Btn>
                </div>
              </div>
            ))
          )}
        </Panel>

        {/* Radar */}
        <Panel title="Interaction Radar" subtitle="Real-time attacker positions">
          <div style={{ padding:"20px 0" }}>
            <RadarViz honeypots={honeypots} attackers={attackers} />
            <div style={{ display:"flex", gap:16, justifyContent:"center", marginTop:16 }}>
              {["critical","high","medium"].map(lvl => {
                const c = THREAT_COLORS[lvl];
                return (
                  <div key={lvl} style={{ display:"flex", alignItems:"center", gap:5 }}>
                    <span style={{ width:8, height:8, borderRadius:"50%", background:c.text, display:"inline-block" }} />
                    <span style={{ fontSize:11, fontFamily:"var(--font-mono)", color:"var(--color-text-secondary)",
                      textTransform:"capitalize", fontWeight:600 }}>{lvl}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </Panel>
      </Grid>

      {/* Attacker Profiles */}
      <Panel title="Attacker Profiles" subtitle="Adversary intelligence from honeypot interactions">
        <DataTable
          columns={[
            { label:"Attacker IP", render:r => <span style={{ fontFamily:"var(--font-mono)", fontSize:11, background:"#fff1f2", color:"#be123c", padding:"3px 9px", borderRadius:4, border:"1px solid #fecdd3", fontWeight:700 }}>{r.ip}</span> },
            { label:"Threat Level", render:r => {
              const c = THREAT_COLORS[r.threatLevel] || THREAT_COLORS.low;
              return <span style={{ fontFamily:"var(--font-mono)", fontSize:11, fontWeight:700, padding:"2px 8px", borderRadius:99, background:c.bg, color:c.text, border:`1px solid ${c.border}` }}>{r.threatLevel?.toUpperCase()}</span>;
            }},
            { label:"Country",     render:r => <span style={{ fontFamily:"var(--font-mono)", fontSize:12 }}>🌍 {r.country || "Unknown"}</span> },
            { label:"Interactions",render:r => <span style={{ fontFamily:"var(--font-mono)", fontSize:13, fontWeight:700, color:"var(--color-text-primary)" }}>{r.interactions ?? r.totalEvents ?? 0}</span> },
            { label:"First Seen",  render:r => <span style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--color-text-tertiary)" }}>{fmtDateTime(r.firstSeen)}</span> },
            { label:"Last Seen",   render:r => <span style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--color-text-tertiary)" }}>{fmtDateTime(r.lastSeen)}</span> },
          ]}
          rows={attackers}
          emptyText="No attackers profiled yet. Deploy honeypots to start capturing attacker data."
        />
      </Panel>

      {/* Deploy Modal */}
      <Modal open={deployModal} onClose={() => setDeployModal(false)} title="Deploy Honeypot"
        footer={<>
          <Btn variant="ghost" onClick={() => setDeployModal(false)}>Cancel</Btn>
          <Btn variant="primary" onClick={() => {
            if (!newHP.name.trim() || !newHP.ip.trim()) { onToast("Name and IP required", "warning"); return; }
            onDeployHoneypot({ ...newHP, port:parseInt(newHP.port)||2222 });
            setDeployModal(false);
            setNewHP({ name:"", type:"ssh", ip:"", port:"2222" });
            onToast("Honeypot deployed: "+newHP.name, "success");
          }}>Deploy Honeypot</Btn>
        </>}>
        <FormGroup label="Honeypot Name">
          <input value={newHP.name} onChange={e => setNewHP(p=>({...p,name:e.target.value}))} placeholder="e.g. SSH-Trap-02" />
        </FormGroup>
        <Grid cols={2} gap={12}>
          <FormGroup label="Service Type">
            <select value={newHP.type} onChange={e => setNewHP(p=>({...p,type:e.target.value}))}>
              {["ssh","http","ftp","smtp","rdp","telnet"].map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
            </select>
          </FormGroup>
          <FormGroup label="Listen Port">
            <input type="number" value={newHP.port} onChange={e => setNewHP(p=>({...p,port:e.target.value}))} placeholder="2222" />
          </FormGroup>
        </Grid>
        <FormGroup label="Bind IP Address">
          <input value={newHP.ip} onChange={e => setNewHP(p=>({...p,ip:e.target.value}))} placeholder="192.168.1.200" />
        </FormGroup>
        <div style={{ padding:"10px 14px", background:"#fffbeb", borderRadius:"var(--r-md)",
          border:"1px solid #fde68a", fontSize:12, color:"#b45309" }}>
          ⚠ Ensure the IP is within your network range and not assigned to a production host. Cowrie/Dionaea must be installed separately.
        </div>
      </Modal>
    </div>
  );
}
