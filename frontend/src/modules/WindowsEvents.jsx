import { useEffect, useMemo, useState } from "react";
import { Panel, Grid, StatCard, Badge, DataTable, EmptyState } from "../components/UI.jsx";
import { events as eventsApi } from "../api/client.js";
import { EVENT_ID_NAMES } from "../data/seed.js";
import { fmtTime } from "../utils/dateFormatter.js";

const EVENT_SEVERITY = {
  4625:{ sev:"HIGH",     color:"#e11d48" },
  7045:{ sev:"CRITICAL", color:"#e11d48" },
  4688:{ sev:"HIGH",     color:"#f59e0b" },
  4740:{ sev:"HIGH",     color:"#e11d48" },
  4698:{ sev:"CRITICAL", color:"#e11d48" },
  4720:{ sev:"MEDIUM",   color:"#8b5cf6" },
  4672:{ sev:"HIGH",     color:"#f59e0b" },
  4624:{ sev:"INFO",     color:"#10b981" },
  7036:{ sev:"INFO",     color:"#0ea5e9" },
};

const CHANNEL_COLORS = {
  Security:    { bg:"#fff1f2", text:"#be123c", border:"#fecdd3" },
  System:      { bg:"#f0f9ff", text:"#0369a1", border:"#bae6fd" },
  Application: { bg:"#f5f3ff", text:"#6d28d9", border:"#ddd6fe" },
};

function inferEventNameFromMessage(message = "") {
  const match = String(message).match(/^\[([^\]]+)\]\s*/);
  if (match?.[1]) return match[1].trim();
  return "";
}

export default function WindowsEvents({ appState }) {
  const { winEvents } = appState;
  const [catalogById, setCatalogById] = useState({});

  const visibleEventIds = useMemo(() => {
    const ids = new Set();
    for (const event of winEvents) {
      const id = Number(event?.eventId);
      if (Number.isFinite(id)) ids.add(id);
    }
    return Array.from(ids);
  }, [winEvents]);

  const sampleEventById = useMemo(() => {
    const map = {};
    for (const event of winEvents) {
      const id = Number(event?.eventId);
      if (!Number.isFinite(id) || map[id]) continue;
      map[id] = event;
    }
    return map;
  }, [winEvents]);

  useEffect(() => {
    const missing = visibleEventIds.filter((id) => catalogById[id] === undefined);
    if (!missing.length) return;

    let active = true;
    const batch = missing.slice(0, 25);

    (async () => {
      const results = await Promise.all(
        batch.map(async (id) => {
          try {
            const entry = await eventsApi.getCatalogEntry(id);
            return [id, entry];
          } catch {
            return [id, { eventId: id, known: false }];
          }
        })
      );

      if (!active) return;
      setCatalogById((prev) => {
        const next = { ...prev };
        for (const [id, entry] of results) {
          next[id] = entry;
        }
        return next;
      });
    })();

    return () => {
      active = false;
    };
  }, [visibleEventIds, catalogById]);

  const resolveEventName = (eventId, sampleEvent) => {
    const id = Number(eventId);
    const catalogEntry = catalogById[id];
    if (catalogEntry?.known && catalogEntry.description) return catalogEntry.description;
    return EVENT_ID_NAMES[id] || inferEventNameFromMessage(sampleEvent?.message) || "Unknown Event";
  };

  const resolveProcessName = (eventId, sampleEvent) => {
    const id = Number(eventId);
    const catalogEntry = catalogById[id];
    if (catalogEntry?.known && catalogEntry.source) return catalogEntry.source;
    if (sampleEvent?.source) return sampleEvent.source;
    return "Unknown Source";
  };

  const total     = winEvents.length;
  const security  = winEvents.filter(e => e.securityRelevant).length;
  const failed    = winEvents.filter(e => e.eventId === 4625).length;
  const critical  = winEvents.filter(e => [7045,4740,4698].includes(e.eventId)).length;

  // Group by event ID
  const idCounts = {};
  winEvents.forEach(e => { idCounts[e.eventId] = (idCounts[e.eventId]||0)+1; });
  const topIds = Object.entries(idCounts).sort((a,b) => b[1]-a[1]).slice(0,8);

  return (
    <div className="page-enter">
      <Grid cols={4} gap={14} style={{ marginBottom:20 }}>
        <StatCard icon="📋" label="Total Events (24h)" value={total}   sub="All channels"   color="#2d6bff" />
        <StatCard icon="🔐" label="Security Events"    value={security} sub="Relevant events" color="#7c3aed" />
        <StatCard icon="🚫" label="Failed Logins"      value={failed}   sub="Event ID 4625"  color="#e11d48" />
        <StatCard icon="⚡" label="Critical Events"    value={critical} sub="Needs review"   color="#f59e0b" />
      </Grid>

      <Grid cols={2} gap={16} style={{ marginBottom:20 }}>
        {/* Live Stream */}
        <Panel title="Live Event Stream"
          subtitle="Windows Event Log API · Polling every 5s"
          actions={
            <div style={{ display:"flex", gap:6 }}>
              {["Security","System","Application"].map(ch => {
                const c = CHANNEL_COLORS[ch];
                return (
                  <span key={ch} style={{ fontSize:10, fontFamily:"var(--font-mono)", fontWeight:700,
                    padding:"2px 7px", borderRadius:99, background:c.bg, color:c.text, border:`1px solid ${c.border}` }}>
                    {ch}
                  </span>
                );
              })}
            </div>
          }
        >
          <div style={{ maxHeight:300, overflowY:"auto" }}>
            {winEvents.length === 0 ? (
              <EmptyState icon="🪟" title="No events yet" sub="Windows Event reader polling…" />
            ) : (
              winEvents.map(e => {
                const meta = EVENT_SEVERITY[e.eventId] || { sev:"INFO", color:"#94a3b8" };
                const ch   = CHANNEL_COLORS[e.channel] || CHANNEL_COLORS.Application;
                return (
                  <div key={e.logId} style={{
                    display:"flex", gap:10, alignItems:"flex-start",
                    padding:"8px 14px", borderBottom:"1px solid #f1f5f9",
                  }}>
                    <span style={{ fontFamily:"var(--font-mono)", fontSize:10,
                      color:"var(--color-text-tertiary)", flexShrink:0, marginTop:1, minWidth:55 }}>
                      {fmtTime(e.eventTime)}
                    </span>
                    <span style={{ fontSize:10, fontFamily:"var(--font-mono)", fontWeight:700,
                      padding:"2px 6px", borderRadius:99, background:ch.bg, color:ch.text,
                      border:`1px solid ${ch.border}`, flexShrink:0 }}>
                      {e.channel}
                    </span>
                    <span style={{ fontFamily:"var(--font-mono)", fontSize:11, fontWeight:700,
                      color: meta.color, flexShrink:0, minWidth:36 }}>{e.eventId}</span>
                    <span style={{ fontSize:12, color:"var(--color-text-secondary)",
                      lineHeight:1.5, overflow:"hidden" }}>
                      {e.message.substring(0,90)}{e.message.length > 90 ? "…" : ""}
                    </span>
                    {e.securityRelevant && (
                      <span style={{ fontSize:9, fontFamily:"var(--font-mono)", fontWeight:700,
                        color:"#be123c", background:"#fff1f2", border:"1px solid #fecdd3",
                        padding:"2px 6px", borderRadius:99, flexShrink:0, marginTop:1 }}>
                        SEC
                      </span>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </Panel>

        {/* Top Event IDs */}
        <Panel title="Top Security Event IDs" subtitle="Frequency analysis">
          <div style={{ padding:"0 4px" }}>
            {topIds.length === 0 ? (
              <EmptyState icon="📊" title="No data" sub="Events will appear after polling" />
            ) : (
              topIds.map(([id, count]) => {
                const meta = EVENT_SEVERITY[+id] || { sev:"INFO", color:"#94a3b8" };
                const pct  = (count / (topIds[0]?.[1] || 1)) * 100;
                return (
                  <div key={id} style={{ padding:"10px 14px", borderBottom:"1px solid #f1f5f9" }}>
                    <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:5 }}>
                      <span style={{ fontFamily:"var(--font-mono)", fontSize:12, fontWeight:700,
                        color:meta.color, minWidth:40 }}>{id}</span>
                      <div style={{ flex:1, minWidth:0 }}>
                        <div style={{ fontSize:12, color:"var(--color-text-secondary)", whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>
                          {resolveEventName(+id, sampleEventById[+id])}
                        </div>
                        <div style={{ fontSize:10, color:"var(--color-text-tertiary)", whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>
                          {resolveProcessName(+id, sampleEventById[+id])}
                        </div>
                      </div>
                      <span style={{ fontFamily:"var(--font-mono)", fontSize:11, fontWeight:700,
                        color:"var(--color-text-primary)" }}>{count}</span>
                      <span style={{ fontSize:10, fontFamily:"var(--font-mono)", fontWeight:700,
                        padding:"2px 7px", borderRadius:99,
                        background:meta.color+"15", color:meta.color, border:`1px solid ${meta.color}33` }}>
                        {meta.sev}
                      </span>
                    </div>
                    <div style={{ height:3, background:"#f1f5f9", borderRadius:99, overflow:"hidden" }}>
                      <div style={{ height:"100%", width:`${pct}%`, background:meta.color,
                        borderRadius:99, transition:"width 0.5s ease" }} />
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </Panel>
      </Grid>

      {/* Full Event Log Table */}
      <Panel title="Event Log Table" subtitle="Full Windows Event Log entries">
        <DataTable
          columns={[
            { label:"Time",      render: r => <span style={{ fontFamily:"var(--font-mono)", fontSize:11 }}>{fmtTime(r.eventTime)}</span> },
            { label:"Channel",   render: r => {
              const c = CHANNEL_COLORS[r.channel] || CHANNEL_COLORS.Application;
              return <span style={{ fontSize:10, fontFamily:"var(--font-mono)", fontWeight:700,
                padding:"2px 7px", borderRadius:99, background:c.bg, color:c.text, border:`1px solid ${c.border}` }}>{r.channel}</span>;
            }},
            { label:"Event ID",  render: r => <span style={{ fontFamily:"var(--font-mono)", fontSize:12, fontWeight:700,
              color: (EVENT_SEVERITY[r.eventId]||{}).color || "#94a3b8" }}>{r.eventId}</span> },
            { label:"Event Name", render: r => <span style={{ fontSize:12, color:"var(--color-text-secondary)" }}>
              {resolveEventName(r.eventId, r)}</span>, wrap:true, maxWidth:"240px" },
            { label:"Level",     render: r => <Badge status={r.level?.toLowerCase()} /> },
            { label:"Process / Source", render: r => <span style={{ fontSize:11, color:"var(--color-text-secondary)" }}>
              {resolveProcessName(r.eventId, r)}</span> },
            { label:"Computer",  key:"computerName", mono:true, dim:true },
            { label:"Message",   render: r => <span style={{ fontSize:12, color:"var(--color-text-secondary)" }}>
              {r.message.substring(0,70)}{r.message.length > 70 ? "…" : ""}</span>, wrap:true, maxWidth:"260px" },
            { label:"Security",  render: r => r.securityRelevant
              ? <span style={{ fontSize:9, fontFamily:"var(--font-mono)", fontWeight:700, color:"#be123c",
                  background:"#fff1f2", border:"1px solid #fecdd3", padding:"2px 6px", borderRadius:99 }}>⚠ YES</span>
              : <span style={{ fontSize:11, color:"var(--color-text-tertiary)" }}>—</span>
            },
          ]}
          rows={winEvents}
          emptyText="No events yet — Windows Event reader polling…"
        />
      </Panel>
    </div>
  );
}
