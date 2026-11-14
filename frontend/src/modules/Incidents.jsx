import { useState, useEffect } from "react";
import { Panel, Grid, StatCard, Badge, Btn, Modal, FormGroup, DataTable, EmptyState } from "../components/UI.jsx";
import { fmtDateTime } from "../utils/dateFormatter.js";
import { incidents as incidentsApi } from "../api/client.js";

const STATUSES = ["open","investigating","contained","resolved","closed"];

function Timeline({ incident, timeline }) {
  // Use actual timeline events from backend if available
  const events = timeline && timeline.length > 0
    ? timeline.map(tl => ({
        type: tl.actionType,
        time: tl.timestamp,
        text: tl.description,
      }))
    : [
        { type: "created", time: incident.createdAt, text: `Incident created — ${incident.severity.toUpperCase()} severity` },
        incident.status !== "open" && { type: "updated", time: incident.createdAt, text: `Status: ${incident.status}` },
        incident.resolvedAt && { type: "resolved", time: incident.resolvedAt, text: "Incident resolved" },
      ].filter(Boolean);

  const dotColors = { 
    created: "#2d6bff", 
    updated: "#f59e0b", 
    note: "#8b5cf6", 
    escalated: "#e11d48",
    contained: "#f59e0b", 
    resolved: "#10b981" 
  };

  return (
    <div style={{ padding: "8px 0" }}>
      {events.map((t, i) => (
        <div key={i} style={{ display: "flex", gap: 12, marginBottom: 14 }}>
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
            <div style={{
              width: 10, height: 10, borderRadius: "50%",
              background: dotColors[t.type] || "#94a3b8", flexShrink: 0, marginTop: 3
            }} />
            {i < events.length - 1 && <div style={{ width: 1.5, flex: 1, background: "#e2e8f0", marginTop: 4 }} />}
          </div>
          <div style={{ flex: 1, paddingBottom: 4 }}>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-tertiary)", marginBottom: 2 }}>
              {fmtDateTime(t.time)}
            </div>
            <div style={{ fontSize: 13, color: "var(--color-text-secondary)" }}>{t.text}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

export default function Incidents({ appState, onCreateIncident, onUpdateIncident, onAddNote, onToast }) {
  const { incidents } = appState;
  const [createModal, setCreateModal] = useState(false);
  const [viewIncident, setViewIncident] = useState(null);
  const [incidentTimeline, setIncidentTimeline] = useState(null);
  const [noteText,    setNoteText]    = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [newInc, setNewInc] = useState({ title:"", description:"", severity:"high", assignedTo:"", affectedAssets:"" });

  // Fetch timeline when viewing an incident
  useEffect(() => {
    if (viewIncident && viewIncident.incidentId) {
      incidentsApi.getTimeline(viewIncident.incidentId)
        .then(tl => setIncidentTimeline(tl))
        .catch(err => {
          console.warn("Failed to fetch incident timeline:", err);
          setIncidentTimeline([]);
        });
    } else {
      setIncidentTimeline(null);
    }
  }, [viewIncident]);

  const open          = incidents.filter(i => i.status === "open").length;
  const investigating = incidents.filter(i => i.status === "investigating").length;
  const contained     = incidents.filter(i => i.status === "contained").length;
  const resolved      = incidents.filter(i => ["resolved","closed"].includes(i.status)).length;

  const filtered = statusFilter ? incidents.filter(i => i.status === statusFilter) : incidents;

  return (
    <div className="page-enter">
      <Grid cols={4} gap={14} style={{ marginBottom:20 }}>
        <StatCard icon="🔴" label="Open"          value={open}          sub="Awaiting action"  color="#e11d48" />
        <StatCard icon="🔎" label="Investigating" value={investigating} sub="In progress"      color="#f59e0b" />
        <StatCard icon="🛡" label="Contained"     value={contained}    sub="Threat isolated"  color="#8b5cf6" />
        <StatCard icon="✅" label="Resolved"      value={resolved}     sub="Closed incidents" color="#10b981" />
      </Grid>

      <Panel title="Incident Register"
        subtitle={`${incidents.length} total incidents`}
        actions={
          <div style={{ display:"flex", gap:8, alignItems:"center" }}>
            <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}
              style={{ width:140, padding:"6px 10px", fontSize:12 }}>
              <option value="">All Status</option>
              {STATUSES.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase()+s.slice(1)}</option>)}
            </select>
            <Btn size="sm" variant="primary" onClick={() => setCreateModal(true)}>+ Create Incident</Btn>
          </div>
        }
      >
        <DataTable
          columns={[
            { label:"ID",         render:r => <span style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"#2d6bff", fontWeight:700 }}>{r.incidentNumber}</span> },
            { label:"Title",      render:r => <span style={{ fontWeight:600, fontSize:13 }}>{r.title}</span>, maxWidth:"200px", wrap:false },
            { label:"Severity",   render:r => <Badge severity={r.severity} /> },
            { label:"Status",     render:r => <Badge status={r.status} />    },
            { label:"Assigned",   key:"assignedTo", dim:true },
            { label:"Assets",     render:r => <span style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"#1340b8", background:"#f0f5ff", padding:"2px 7px", borderRadius:4 }}>{r.affectedAssets}</span> },
            { label:"Created",    render:r => <span style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--color-text-tertiary)" }}>{fmtDateTime(r.createdAt)}</span> },
            { label:"Actions",    render:r => (
              <div style={{ display:"flex", gap:6 }}>
                <Btn size="xs" variant="ghost" onClick={() => setViewIncident(r)}>View</Btn>
                <Btn size="xs" variant="amber" onClick={() => {
                  const next = STATUSES[STATUSES.indexOf(r.status)+1] || "closed";
                  onUpdateIncident(r.incidentId, next);
                  onToast(`Incident ${r.incidentNumber} → ${next}`, "success");
                }} disabled={r._demo}>Update</Btn>
              </div>
            )},
          ]}
          rows={filtered}
          emptyText="No incidents match the filter"
        />
      </Panel>

      {/* View/Detail Modal */}
      <Modal open={!!viewIncident} onClose={() => setViewIncident(null)} title={viewIncident?.incidentNumber || "Incident Detail"}
        width={560}
        footer={<>
          <Btn variant="ghost" onClick={() => setViewIncident(null)}>Close</Btn>
          {viewIncident && !["resolved","closed"].includes(viewIncident.status) && (
            <Btn variant="primary" onClick={() => {
              const next = STATUSES[STATUSES.indexOf(viewIncident.status)+1] || "closed";
              onUpdateIncident(viewIncident.incidentId, next);
              setViewIncident(p => p ? { ...p, status:next } : p);
              onToast(`Status → ${next}`, "success");
            }} disabled={viewIncident._demo}>Advance Status →</Btn>
          )}
        </>}>
        {viewIncident && (
          <div>
            <Grid cols={3} gap={10} style={{ marginBottom:16 }}>
              {[
                { l:"Severity",    v:<Badge severity={viewIncident.severity} /> },
                { l:"Status",      v:<Badge status={viewIncident.status} />     },
                { l:"Assigned",    v:<span style={{ fontWeight:600, fontSize:13 }}>{viewIncident.assignedTo||"—"}</span> },
              ].map(({ l,v }) => (
                <div key={l}>
                  <div style={{ fontSize:10, fontFamily:"var(--font-mono)", color:"var(--color-text-tertiary)",
                    textTransform:"uppercase", letterSpacing:"0.05em", marginBottom:5 }}>{l}</div>
                  {v}
                </div>
              ))}
            </Grid>
            <div style={{ marginBottom:14 }}>
              <div style={{ fontSize:10, fontFamily:"var(--font-mono)", color:"var(--color-text-tertiary)",
                textTransform:"uppercase", letterSpacing:"0.05em", marginBottom:6, fontWeight:600 }}>Title</div>
              <div style={{ fontFamily:"var(--font-display)", fontWeight:700, fontSize:15,
                color:"var(--color-text-primary)" }}>{viewIncident.title}</div>
            </div>
            {viewIncident.description && (
              <div style={{ padding:"12px 14px", background:"#f8fafc", borderRadius:"var(--r-md)",
                border:"1px solid var(--color-border)", fontSize:13, color:"var(--color-text-secondary)",
                marginBottom:14, lineHeight:1.6 }}>{viewIncident.description}</div>
            )}
            <div style={{ fontSize:10, fontFamily:"var(--font-mono)", color:"var(--color-text-tertiary)",
              textTransform:"uppercase", letterSpacing:"0.05em", marginBottom:8, fontWeight:600 }}>Timeline</div>
            <Timeline incident={viewIncident} timeline={incidentTimeline} />
            <div style={{ marginTop:14, borderTop:"1.5px solid var(--color-border)", paddingTop:14 }}>
              <FormGroup label="Add Note">
                <textarea value={noteText} onChange={e => setNoteText(e.target.value)}
                  placeholder="Investigation notes, findings, actions taken…" disabled={viewIncident._demo} />
              </FormGroup>
              <Btn size="sm" variant="outline" onClick={async () => {
                if (!noteText.trim()) return;
                try {
                  await onAddNote(viewIncident.incidentId, noteText);
                  const tl = await incidentsApi.getTimeline(viewIncident.incidentId);
                  setIncidentTimeline(tl);
                  setNoteText("");
                  onToast("Note added to incident timeline", "success");
                } catch (err) {
                  onToast(err?.message || "Failed to add note", "error");
                }
              }} disabled={viewIncident._demo}>Add Note</Btn>
            </div>
          </div>
        )}
      </Modal>

      {/* Create Incident Modal */}
      <Modal open={createModal} onClose={() => setCreateModal(false)} title="Create Incident"
        footer={<>
          <Btn variant="ghost" onClick={() => setCreateModal(false)}>Cancel</Btn>
          <Btn variant="primary" onClick={() => {
            if (!newInc.title.trim()) { onToast("Title required", "warning"); return; }
            onCreateIncident(newInc);
            setCreateModal(false);
            setNewInc({ title:"", description:"", severity:"high", assignedTo:"", affectedAssets:"" });
            onToast("Incident created", "success");
          }}>Create Incident</Btn>
        </>}>
        <FormGroup label="Title">
          <input value={newInc.title} onChange={e => setNewInc(p=>({...p,title:e.target.value}))} placeholder="Brief description of the security incident" />
        </FormGroup>
        <Grid cols={2} gap={12}>
          <FormGroup label="Severity">
            <select value={newInc.severity} onChange={e => setNewInc(p=>({...p,severity:e.target.value}))}>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </FormGroup>
          <FormGroup label="Assigned To">
            <input value={newInc.assignedTo} onChange={e => setNewInc(p=>({...p,assignedTo:e.target.value}))} placeholder="analyst1" />
          </FormGroup>
        </Grid>
        <FormGroup label="Affected Assets">
          <input value={newInc.affectedAssets} onChange={e => setNewInc(p=>({...p,affectedAssets:e.target.value}))} placeholder="192.168.1.1, server01, DESKTOP-…" />
        </FormGroup>
        <FormGroup label="Description">
          <textarea value={newInc.description} onChange={e => setNewInc(p=>({...p,description:e.target.value}))} placeholder="Detailed incident description, indicators of compromise, affected systems…" />
        </FormGroup>
      </Modal>
    </div>
  );
}
