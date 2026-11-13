import { useState } from "react";
import { Panel, Grid, StatCard, Badge, IPPill, Btn, Modal, FormGroup, FeedItem, DataTable, LivePulse, EmptyState, Select } from "../components/UI.jsx";
import { fmtTime } from "../utils/dateFormatter.js";

const sev = { 1:"Low", 2:"Medium", 3:"High", 4:"Critical" };
const sevColor = { 1:"#10b981", 2:"#8b5cf6", 3:"#f59e0b", 4:"#e11d48" };

const PRESET_IDS_RULES = [
  {
    slug: "ssh-bruteforce",
    label: "SSH Brute Force",
    description: "Detects 10 failed SSH logins from the same source within 60s.",
    rule: {
      ruleName: "SSH Brute Force",
      ruleContent: "alert tcp any any -> $HOME_NET 22 (msg:\"SSH Brute Force\"; flow:to_server,established; detection_filter:track by_src, count 10, seconds 60; classtype:attempted-admin; sid:200001; rev:1;)",
      ruleType: "snort",
      severity: 3,
      sourceIpPattern: "*",
      destIpPattern: "*",
      portPattern: "22",
      protocolPattern: "TCP",
      payloadPattern: null,
    },
  },
  {
    slug: "http-sqli",
    label: "HTTP SQL Injection",
    description: "Flags classic SQLi keywords inside HTTP GET payloads.",
    rule: {
      ruleName: "HTTP SQL Injection",
      ruleContent: "alert tcp any any -> $HOME_NET 80 (msg:\"HTTP SQL Injection Attempt\"; content:\"select\"; nocase; http_uri; pcre:\"/(union|select|sleep|benchmark)/Ui\"; classtype:web-application-attack; sid:200002; rev:1;)",
      ruleType: "snort",
      severity: 4,
      sourceIpPattern: "*",
      destIpPattern: "*",
      portPattern: "80",
      protocolPattern: "TCP",
      payloadPattern: "select|union|sleep|benchmark",
    },
  },
  {
    slug: "smb-ghost",
    label: "SMB Ghost",
    description: "Watches for crafted SMB packets hitting port 445.",
    rule: {
      ruleName: "SMB Ghost Probe",
      ruleContent: "alert tcp any any -> $HOME_NET 445 (msg:\"SMB Ghost Probe\"; content:\"\x00\x00\x00\x90\xff\x53\x4d\x42\x72\"; depth:10; classtype:attempted-admin; sid:200003; rev:1;)",
      ruleType: "snort",
      severity: 4,
      sourceIpPattern: "*",
      destIpPattern: "*",
      portPattern: "445",
      protocolPattern: "TCP",
      payloadPattern: "FF SMB",
    },
  },
  {
    slug: "dns-tunnel",
    label: "DNS Tunneling",
    description: "Alerts on long TXT queries indicative of tunneling.",
    rule: {
      ruleName: "DNS Tunnel Detection",
      ruleContent: "alert udp any any -> $HOME_NET 53 (msg:\"DNS Tunneling Suspected\"; content:\"\x00\x10\x00\x01\"; byte_test:1,>,60,10; classtype:trojan-activity; sid:200004; rev:1;)",
      ruleType: "snort",
      severity: 2,
      sourceIpPattern: "*",
      destIpPattern: "*",
      portPattern: "53",
      protocolPattern: "UDP",
      payloadPattern: null,
    },
  },
];

export default function Network({ appState, onAddRule, onDeleteRule, onToggleRule, onUpdateAlertStatus, onToast }) {
  const { alerts, idsRules, capturePackets, captureRunning, trafficFeed } = appState;
  const [selectedPacketIdx, setSelectedPacketIdx] = useState(0);
  const [presetBusy, setPresetBusy] = useState(null);
  const [ruleBusy, setRuleBusy] = useState(null);
  const [deleteBusy, setDeleteBusy] = useState(null);
  const packetRows = (trafficFeed || []).slice(0, 80).map((p, idx) => ({
    no: idx + 1,
    time: p.time || "--:--:--",
    src: p.src || "0.0.0.0",
    dst: p.dst || "0.0.0.0",
    protocol: (p.protocol || "OTHER").toUpperCase(),
    length: p.size || 0,
    port: p.port || "-",
    info: `${(p.protocol || "IP").toUpperCase()} ${p.src || "?"} → ${p.dst || "?"}${p.port ? `:${p.port}` : ""}`,
  }));
  const selectedPacket = packetRows[selectedPacketIdx] || null;
  const protoColor = (proto) => ({ TCP:"#2d6bff", UDP:"#0ea5e9", ICMP:"#f59e0b", DNS:"#8b5cf6" }[proto] || "#64748b");

  const handlePresetAction = async (preset) => {
    if (presetBusy) return;
    setPresetBusy(preset.slug);
    try {
      const existing = idsRules.find(r => r.ruleName === preset.rule.ruleName);
      if (!existing) {
        await onAddRule(preset.rule);
      } else {
        await onToggleRule(existing.ruleId);
      }
    } catch (err) {
      onToast?.(`Preset action failed: ${err.message || "unknown error"}`, "error");
    } finally {
      setPresetBusy(null);
    }
  };

  const handleRuleToggle = async (ruleId) => {
    setRuleBusy(ruleId);
    try {
      await onToggleRule(ruleId);
    } catch (err) {
      onToast?.(`Unable to toggle rule: ${err.message || "unknown"}`, "error");
    } finally {
      setRuleBusy(null);
    }
  };

  const handleRuleDelete = async (ruleId) => {
    setDeleteBusy(ruleId);
    try {
      await onDeleteRule(ruleId);
    } catch (err) {
      onToast?.(`Delete failed: ${err.message || "unknown"}`, "error");
    } finally {
      setDeleteBusy(null);
    }
  };

  return (
    <div className="page-enter">
      {/* Stats */}
      <Grid cols={4} gap={14} style={{ marginBottom:20 }}>
        <StatCard icon="📦" label="Packets Captured" value={capturePackets >= 1000 ? (capturePackets/1000).toFixed(1)+"K" : capturePackets}
          sub="This session" color="#2d6bff" />
        <StatCard icon="🚨" label="Total Alerts"   value={alerts.length}  sub="All time"    color="#e11d48" />
        <StatCard icon="⚡" label="Critical/High"  value={(alerts.filter(a => a.severity === "CRITICAL").length) + (alerts.filter(a => a.severity === "HIGH").length)} sub="Needs attention" color="#f59e0b" />
        <StatCard icon="📋" label="Active Rules"   value={idsRules.filter(r => r.active).length}    sub={`of ${idsRules.length} total`} color="#10b981" />
      </Grid>

      {/* Capture Status Bar */}
      <div style={{
        background:"#fff", border:"1.5px solid var(--color-border)", borderRadius:"var(--r-lg)",
        padding:"12px 18px", marginBottom:20, display:"flex", alignItems:"center",
        gap:20, flexWrap:"wrap", boxShadow:"var(--shadow-xs)",
      }}>
        <LivePulse active={captureRunning} label={captureRunning ? "CAPTURING" : "INACTIVE"} />
        {[
          { label:"Interface", val:"Auto-detect (Npcap)" },
          { label:"Mode",      val:"Promiscuous" },
          { label:"New Alerts",val:alerts.filter(a => a.status === "new").length },
          { label:"Rules",     val:`${idsRules.filter(r => r.active).length} active` },
        ].map(s => (
          <div key={s.label} style={{ display:"flex", alignItems:"center", gap:6 }}>
            <span style={{ fontSize:11, color:"var(--color-text-tertiary)", fontFamily:"var(--font-mono)", textTransform:"uppercase" }}>{s.label}</span>
            <span style={{ fontSize:11, fontFamily:"var(--font-mono)", fontWeight:700,
              color:"var(--color-text-primary)", background:"#f1f5f9",
              padding:"2px 8px", borderRadius:"var(--r-sm)" }}>{s.val}</span>
          </div>
        ))}
      </div>

      <Panel title="Live Traffic Analyzer" subtitle="Wireshark-style packet list and decode view" padding="0">
        <div style={{ borderBottom:"1.5px solid #e2e8f0", background:"#f8fafc", padding:"10px 14px", display:"flex", gap:12, alignItems:"center", flexWrap:"wrap" }}>
          {["TCP", "UDP", "ICMP", "OTHER"].map((proto) => (
            <span key={proto} style={{ display:"inline-flex", alignItems:"center", gap:6, fontFamily:"var(--font-mono)", fontSize:10, color:"#475569", background:"#fff", border:"1px solid #e2e8f0", borderRadius:99, padding:"3px 8px" }}>
              <span style={{ width:8, height:8, borderRadius:"50%", background:protoColor(proto), display:"inline-block" }} />
              {proto}
            </span>
          ))}
          <span style={{ marginLeft:"auto", fontFamily:"var(--font-mono)", fontSize:10, color:"#64748b" }}>
            Showing {packetRows.length} packets
          </span>
        </div>

        <div style={{ display:"grid", gridTemplateColumns:"1fr", minHeight:600 }}>
          <div style={{ overflow:"auto", maxHeight:400 }}>
            <table style={{ width:"100%", borderCollapse:"collapse", fontSize:12 }}>
              <thead style={{ position:"sticky", top:0, zIndex:2 }}>
                <tr style={{ background:"#eef2ff", borderBottom:"1.5px solid #dbeafe" }}>
                  {["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"].map((h) => (
                    <th key={h} style={{ textAlign:"left", padding:"8px 10px", fontFamily:"var(--font-mono)", fontSize:10, color:"#475569", textTransform:"uppercase", letterSpacing:"0.04em", whiteSpace:"nowrap" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {packetRows.length === 0 ? (
                  <tr><td colSpan={7} style={{ padding:"24px 12px", color:"#64748b", textAlign:"center" }}>No packet frames yet. Start capture to inspect traffic.</td></tr>
                ) : packetRows.map((r, idx) => {
                  const selected = idx === selectedPacketIdx;
                  return (
                    <tr
                      key={idx}
                      onClick={() => setSelectedPacketIdx(idx)}
                      style={{
                        cursor:"pointer",
                        background:selected ? "#dbeafe" : idx % 2 ? "#fafcff" : "#ffffff",
                        borderBottom:"1px solid #eef2f7",
                      }}
                    >
                      <td style={{ padding:"7px 10px", fontFamily:"var(--font-mono)", color:"#64748b" }}>{r.no}</td>
                      <td style={{ padding:"7px 10px", fontFamily:"var(--font-mono)", color:"#334155", whiteSpace:"nowrap" }}>{r.time}</td>
                      <td style={{ padding:"7px 10px", fontFamily:"var(--font-mono)", color:"#0f172a" }}>{r.src}</td>
                      <td style={{ padding:"7px 10px", fontFamily:"var(--font-mono)", color:"#0f172a" }}>{r.dst}</td>
                      <td style={{ padding:"7px 10px" }}>
                        <span style={{ fontFamily:"var(--font-mono)", fontSize:10, fontWeight:700, color:protoColor(r.protocol), background:protoColor(r.protocol)+"20", border:`1px solid ${protoColor(r.protocol)}55`, borderRadius:99, padding:"2px 7px" }}>{r.protocol}</span>
                      </td>
                      <td style={{ padding:"7px 10px", fontFamily:"var(--font-mono)", color:"#334155" }}>{r.length}</td>
                      <td style={{ padding:"7px 10px", color:"#334155", whiteSpace:"nowrap", maxWidth:260, overflow:"hidden", textOverflow:"ellipsis" }}>{r.info}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        <div style={{ background:"#f8fafc", padding:"12px 14px", borderTop:"1.5px solid #e2e8f0", marginTop:16 }}>
          <div style={{ fontFamily:"var(--font-display)", fontWeight:700, fontSize:13, color:"#1e293b", marginBottom:10 }}>Packet Detail</div>
            {selectedPacket ? (
              <>
                <div style={{ background:"#fff", border:"1px solid #dbeafe", borderRadius:10, padding:"10px 12px", marginBottom:10 }}>
                  <div style={{ fontSize:10, fontFamily:"var(--font-mono)", color:"#64748b", textTransform:"uppercase" }}>Frame</div>
                  <div style={{ marginTop:6, fontSize:12, color:"#0f172a", lineHeight:1.6 }}>
                    Frame {selectedPacket.no}: {selectedPacket.length} bytes on wire<br />
                    Arrival Time: {selectedPacket.time}<br />
                    Encapsulation: Ethernet II / IPv4
                  </div>
                </div>
                <div style={{ background:"#fff", border:"1px solid #e2e8f0", borderRadius:10, padding:"10px 12px", marginBottom:10 }}>
                  <div style={{ fontSize:10, fontFamily:"var(--font-mono)", color:"#64748b", textTransform:"uppercase" }}>Internet Protocol</div>
                  <div style={{ marginTop:6, fontSize:12, color:"#0f172a", lineHeight:1.6 }}>
                    Source: {selectedPacket.src}<br />
                    Destination: {selectedPacket.dst}<br />
                    TTL: 64 (estimated)
                  </div>
                </div>
                <div style={{ background:"#fff", border:"1px solid #e2e8f0", borderRadius:10, padding:"10px 12px" }}>
                  <div style={{ fontSize:10, fontFamily:"var(--font-mono)", color:"#64748b", textTransform:"uppercase" }}>Transport / Application</div>
                  <div style={{ marginTop:6, fontSize:12, color:"#0f172a", lineHeight:1.6 }}>
                    Protocol: {selectedPacket.protocol}<br />
                    Port: {selectedPacket.port}<br />
                    Info: {selectedPacket.info}
                  </div>
                </div>
              </>
            ) : (
              <div style={{ color:"#64748b", fontSize:12 }}>Select a packet row to inspect decoded details.</div>
            )}
          </div>
      </Panel>

      {/* IDS Rules */}
      <div style={{ marginTop: 24 }}>
        <Panel title="Predefined IDS Profiles" subtitle="One-click activation of common signatures" padding="0">
          <div style={{ padding: "16px" }}>
            <Grid cols={2} gap={12}>
              {PRESET_IDS_RULES.map((preset) => {
                const existing = idsRules.find(r => r.ruleName === preset.rule.ruleName);
                const isActive = existing?.active;
                const actionLabel = !existing ? "Activate" : isActive ? "Deactivate" : "Activate";
                return (
                  <div key={preset.slug} style={{
                    border: "1.5px solid var(--color-border)",
                    borderRadius: "var(--r-lg)",
                    padding: "14px 16px",
                    background: "var(--color-surface)",
                    display: "flex",
                    flexDirection: "column",
                    gap: 8,
                  }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10 }}>
                      <div>
                        <div style={{ fontWeight: 700, fontSize: 13, color: "var(--color-text-primary)" }}>{preset.label}</div>
                        <div style={{ fontSize: 11, color: "var(--color-text-tertiary)" }}>{preset.description}</div>
                      </div>
                      <Badge size="xs" severity={sev[ preset.rule.severity ] || "Medium"} label={sev[preset.rule.severity] || "Medium"} />
                    </div>
                    <Btn
                      size="sm"
                      variant={isActive ? "danger" : "outline"}
                      onClick={() => handlePresetAction(preset)}
                      disabled={presetBusy === preset.slug}
                    >
                      {presetBusy === preset.slug ? "Working..." : actionLabel}
                    </Btn>
                    {existing && (
                      <div style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--color-text-tertiary)" }}>
                        Rule #{existing.ruleId} · {existing.active ? "Active" : "Disabled"}
                      </div>
                    )}
                  </div>
                );
              })}
            </Grid>
          </div>
        </Panel>
      </div>

      <div style={{ marginTop: 20 }}>
        <Panel title="Active IDS Rules" subtitle="Toggle or delete live detection signatures" padding="0">
          {(!idsRules || idsRules.length === 0) ? (
            <EmptyState icon="🛑" title="No IDS rules" sub="Add or activate presets to begin inspection" />
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                <thead>
                  <tr style={{ background: "#f8fafc", borderBottom: "1px solid #e2e8f0" }}>
                    {['Name','Type','Severity','Patterns','Status','Actions'].map((col) => (
                      <th key={col} style={{ textAlign: "left", padding: "10px 14px", fontFamily: "var(--font-mono)", fontSize: 10, color: "#475569", textTransform: "uppercase", letterSpacing: "0.05em" }}>{col}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {idsRules.map((rule) => (
                    <tr key={rule.ruleId} style={{ borderBottom: "1px solid #f1f5f9" }}>
                      <td style={{ padding: "10px 14px" }}>
                        <div style={{ fontWeight: 600, color: "var(--color-text-primary)" }}>{rule.ruleName}</div>
                        <div style={{ fontSize: 11, color: "var(--color-text-tertiary)" }}>SID {rule.ruleId}</div>
                      </td>
                      <td style={{ padding: "10px 14px", fontFamily: "var(--font-mono)", fontSize: 11 }}>{(rule.ruleType || "custom").toUpperCase()}</td>
                      <td style={{ padding: "10px 14px" }}>
                        <span style={{
                          fontSize: 11,
                          fontFamily: "var(--font-mono)",
                          padding: "2px 8px",
                          borderRadius: 99,
                          background: (sevColor[rule.severity] || "#64748b") + "25",
                          color: sevColor[rule.severity] || "#64748b",
                        }}>{sev[rule.severity] || "Unknown"}</span>
                      </td>
                      <td style={{ padding: "10px 14px", fontSize: 11, color: "var(--color-text-tertiary)", fontFamily: "var(--font-mono)" }}>
                        {(rule.portPattern || rule.protocolPattern || rule.payloadPattern || "-")}
                      </td>
                      <td style={{ padding: "10px 14px" }}>
                        <Badge size="xs" status={rule.active ? "active" : "inactive"} />
                      </td>
                      <td style={{ padding: "10px 14px", display: "flex", gap: 8 }}>
                        <Btn
                          size="xs"
                          variant={rule.active ? "ghost" : "success"}
                          onClick={() => handleRuleToggle(rule.ruleId)}
                          disabled={ruleBusy === rule.ruleId}
                        >
                          {ruleBusy === rule.ruleId ? "Saving..." : rule.active ? "Deactivate" : "Activate"}
                        </Btn>
                        <Btn
                          size="xs"
                          variant="danger"
                          onClick={() => handleRuleDelete(rule.ruleId)}
                          disabled={deleteBusy === rule.ruleId}
                        >
                          {deleteBusy === rule.ruleId ? "Removing..." : "Delete"}
                        </Btn>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
