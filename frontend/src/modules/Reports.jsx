import { useEffect, useState } from "react";
import { Panel, Grid, StatCard, Btn, FormGroup, EmptyState, Badge } from "../components/UI.jsx";
import { reports as reportsApi } from "../api/client.js";
import { saveBlobWithPicker, triggerBrowserDownload } from "../utils/fileDownload.js";
import { fmtISODate, fmtFullDateTime, fmtDateTime, now } from "../utils/dateFormatter.js";
import jsPDF from "jspdf";

const TEMPLATES = [
  { id:1, name:"Security Summary",       type:"security",      desc:"24-hour threat overview — alerts, incidents, malware detections",    icon:"security" },
  { id:2, name:"Compliance Report",      type:"compliance",    desc:"Audit-ready log exports, access records, policy change events",       icon:"compliance" },
  { id:3, name:"Executive Dashboard",    type:"executive",     desc:"High-level KPIs and risk posture for C-suite presentation",           icon:"executive" },
  { id:4, name:"Vulnerability Report",   type:"vulnerability", desc:"Full findings with CVSS scores, CVE references, and remediation steps",icon:"vulnerability" },
  { id:5, name:"Windows Event Report",   type:"windows-events",desc:"System event logs with Event IDs, levels, users, channels, and security context", icon:"windows-events" },
];

const FORMAT_COLORS = {
  pdf:  { bg:"#fff1f2", text:"#be123c", border:"#fecdd3" },
  html: { bg:"#f0f9ff", text:"#0369a1", border:"#bae6fd" },
  csv:  { bg:"#ecfdf5", text:"#047857", border:"#a7f3d0" },
  json: { bg:"#f5f3ff", text:"#6d28d9", border:"#ddd6fe" },
};

function ReportTemplateIcon({ type }) {
  const colors = { security:"#2563eb", compliance:"#0f766e", executive:"#0891b2", vulnerability:"#d97706", "windows-events":"#475569" };
  const color = colors[type] || "#2d6bff";
  const common = { width:20, height:20, viewBox:"0 0 24 24", fill:"none", stroke:color, strokeWidth:1.8, strokeLinecap:"round", strokeLinejoin:"round", "aria-hidden":true };
  if (type === "security") return <svg {...common}><path d="M12 3 20 7v5c0 4.5-3.1 7.6-8 9-4.9-1.4-8-4.5-8-9V7l8-4Z" /><path d="m9 12 2 2 4-4" /></svg>;
  if (type === "compliance") return <svg {...common}><rect x="6" y="3" width="12" height="18" rx="2" /><path d="M9 3h6v3H9zM9 11h6M9 15h6M9 18h3" /></svg>;
  if (type === "executive") return <svg {...common}><path d="M5 19V9M12 19V5M19 19v-7" /><path d="M3 19h18M5 7l4-3 4 2 5-4" /></svg>;
  if (type === "vulnerability") return <svg {...common}><circle cx="10.5" cy="10.5" r="6" /><path d="m15 15 5 5M10.5 7.5v6M7.5 10.5h6" /></svg>;
  return <svg {...common}><rect x="4" y="4" width="16" height="16" rx="2" /><path d="M8 8h8M8 12h8M8 16h5" /></svg>;
}

function createMockReportBlob(template, format, appState, synced30d) {
  const currentNow = now();
  const stamp = fmtISODate(currentNow);
  const baseName = `${template.name.replace(/\s+/g, "_")}_${stamp}`;
  const summarySource = synced30d?.summary || {};
  const syncedData = synced30d?.data || {};
  const summary = {
    alerts30d: summarySource.alerts ?? appState.alerts.length,
    openIncidents: summarySource.openIncidents ?? appState.incidents.filter(i => ["open", "investigating"].includes(i.status)).length,
    infectedFiles: summarySource.infectedFiles ?? appState.malwareScans.filter(s => s.scanResult === "infected").length,
    criticalVulns: appState.vulnFindings.filter(f => f.severity === "critical").length,
    windowsEvents: summarySource.windowsEvents ?? appState.winEvents.length,
    windowsSecurityEvents: summarySource.windowsSecurityEvents ?? appState.winEvents.filter(e => e.securityRelevant).length,
  };
  const latestWinEvents = (syncedData.winEvents || appState.winEvents || []).slice(0, 12);
  const cveRecords = syncedData.cveRecords || [];
  const reportChecks = syncedData.checks || [];

  if (format === "pdf") {
    const doc = new jsPDF({ unit: "pt", format: "a4" });
    const pageWidth = 595.28;
    const pageHeight = 841.89;
    const marginX = 46;
    const primaryBlue = [37, 99, 235];
    const darkBlue = [30, 64, 175];
    const lightBlue = [219, 234, 254];

    // Branded top header bar
    doc.setFillColor(primaryBlue[0], primaryBlue[1], primaryBlue[2]);
    doc.rect(0, 0, pageWidth, 112, "F");
    doc.setFillColor(darkBlue[0], darkBlue[1], darkBlue[2]);
    doc.rect(0, 96, pageWidth, 16, "F");

    // Logo mark (simple vector style for reliability)
    doc.setFillColor(255, 255, 255);
    doc.circle(marginX + 16, 56, 16, "F");
    doc.setTextColor(primaryBlue[0], primaryBlue[1], primaryBlue[2]);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(12);
    doc.text("SG", marginX + 8, 60);

    // Branding + report heading
    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(16);
    doc.text("KavachOps AI SOC Platform", marginX + 40, 50);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(10);
    doc.text("Security Intelligence Report", marginX + 40, 68);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(20);
    doc.text(template.name, marginX, 142);

    doc.setFont("helvetica", "normal");
    doc.setFontSize(10);
    doc.setTextColor(60, 72, 88);
    doc.text(`Generated: ${fmtFullDateTime(currentNow)}`, marginX, 162);
    doc.text(`Template: ${template.type.toUpperCase()}`, pageWidth - marginX - 128, 162);

    // Snapshot section container
    doc.setFillColor(lightBlue[0], lightBlue[1], lightBlue[2]);
    doc.roundedRect(marginX, 184, pageWidth - marginX * 2, 140, 8, 8, "F");
    doc.setTextColor(darkBlue[0], darkBlue[1], darkBlue[2]);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.text("SOC Snapshot", marginX + 14, 208);

    const cards = [
      { label: "Alerts (30d)", value: String(summary.alerts30d) },
      { label: "Open Incidents", value: String(summary.openIncidents) },
      { label: "Infected Files", value: String(summary.infectedFiles) },
      { label: "Critical Vulns", value: String(summary.criticalVulns) },
    ];

    let cardX = marginX + 14;
    cards.forEach((card) => {
      doc.setFillColor(255, 255, 255);
      doc.roundedRect(cardX, 222, 122, 84, 6, 6, "F");
      doc.setDrawColor(191, 219, 254);
      doc.roundedRect(cardX, 222, 122, 84, 6, 6);
      doc.setTextColor(71, 85, 105);
      doc.setFont("helvetica", "normal");
      doc.setFontSize(9);
      doc.text(card.label, cardX + 10, 244);
      doc.setTextColor(primaryBlue[0], primaryBlue[1], primaryBlue[2]);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(24);
      doc.text(card.value, cardX + 10, 282);
      cardX += 132;
    });

    // Description and notes
    doc.setTextColor(30, 41, 59);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.text("Report Overview", marginX, 360);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(11);
    const wrappedDesc = doc.splitTextToSize(template.desc, pageWidth - marginX * 2);
    doc.text(wrappedDesc, marginX, 382);

    doc.setTextColor(71, 85, 105);
    doc.setFontSize(10);
    doc.text("This document is generated by KavachOps AI frontend reporting for operational visibility.", marginX, 430);

    let nextSectionY = 450;
    if (reportChecks.length) {
      const palette = {
        pass: { text: [22, 101, 52] },
        warn: { text: [190, 18, 60] },
        info: { text: [30, 64, 175] },
      };
      doc.setTextColor(30, 41, 59);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(13);
      doc.text("Data Checks", marginX, nextSectionY);
      nextSectionY += 18;
      reportChecks.slice(0, 4).forEach((check) => {
        const colors = palette[check.status] || palette.info;
        doc.setTextColor(colors.text[0], colors.text[1], colors.text[2]);
        doc.setFont("helvetica", "bold");
        doc.setFontSize(10);
        doc.text(`${check.label} — ${check.status.toUpperCase()}`, marginX, nextSectionY);
        nextSectionY += 13;
        doc.setTextColor(71, 85, 105);
        doc.setFont("helvetica", "normal");
        doc.text(check.detail, marginX, nextSectionY);
        nextSectionY += 15;
      });
    }

    if (template.type === "windows-events") {
      const windowsStart = Math.max(nextSectionY + 20, 468);
      doc.setTextColor(30, 41, 59);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(13);
      doc.text("Windows Event Log Details", marginX, windowsStart);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(10);
      doc.setTextColor(51, 65, 85);
      doc.text(
        `Total Events: ${summary.windowsEvents}  |  Security Relevant: ${summary.windowsSecurityEvents}`,
        marginX,
        windowsStart + 18
      );

      let y = windowsStart + 38;
      latestWinEvents.slice(0, 6).forEach((evt) => {
        if (y > 760) return;
        const head = `[${evt.channel || "N/A"}] Event ${evt.eventId || "-"} · ${evt.level || "Info"} · ${evt.userName || "Unknown user"}`;
        const detail = `${evt.computerName || "Unknown host"} · ${evt.eventTime ? fmtFullDateTime(evt.eventTime) : "N/A"}`;
        const msg = String(evt.message || "No message").slice(0, 110);
        doc.setTextColor(30, 64, 175);
        doc.setFont("helvetica", "bold");
        doc.text(head, marginX, y);
        y += 13;
        doc.setTextColor(71, 85, 105);
        doc.setFont("helvetica", "normal");
        doc.text(detail, marginX, y);
        y += 12;
        doc.text(msg, marginX, y);
        y += 16;
      });
    }

    // Footer branding strip
    doc.setFillColor(primaryBlue[0], primaryBlue[1], primaryBlue[2]);
    doc.rect(0, pageHeight - 32, pageWidth, 32, "F");
    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.text("KavachOps AI SOC Platform  |  Confidential", marginX, pageHeight - 13);

    return {
      blob: doc.output("blob"),
      fileName: `${baseName}.pdf`,
      mime: "application/pdf",
    };
  }

  if (format === "csv") {
    const csv = template.type === "windows-events"
      ? [
          "logId,eventId,channel,level,source,computerName,userName,eventTime,securityRelevant,message",
          ...latestWinEvents.map((e) => [
            e.logId,
            e.eventId,
            `"${(e.channel || "").replace(/"/g, "'")}"`,
            `"${(e.level || "").replace(/"/g, "'")}"`,
            `"${(e.source || "").replace(/"/g, "'")}"`,
            `"${(e.computerName || "").replace(/"/g, "'")}"`,
            `"${(e.userName || "").replace(/"/g, "'")}"`,
            `"${e.eventTime || ""}"`,
            e.securityRelevant ? "true" : "false",
            `"${String(e.message || "").replace(/"/g, "'")}"`,
          ].join(",")),
        ].join("\n")
      : template.type === "vulnerability"
        ? [
            "cveId,totalFindings,critical,high,medium,low,cvssScore,lastObserved",
            ...(cveRecords.length ? cveRecords : [{ cveId:"N/A", totalFindings:0, criticalCount:0, highCount:0, mediumCount:0, lowCount:0, cvssScore:"", lastObserved:"" }])
              .map((record) => [
                record.cveId,
                record.totalFindings,
                record.criticalCount,
                record.highCount,
                record.mediumCount,
                record.lowCount,
                record.cvssScore ?? "",
                record.lastObserved ?? ""
              ].join(",")),
          ].join("\n")
      : [
          "metric,value",
          `alerts30d,${summary.alerts30d}`,
          `openIncidents,${summary.openIncidents}`,
          `infectedFiles,${summary.infectedFiles}`,
          `criticalVulnerabilities,${summary.criticalVulns}`,
        ].join("\n");

    return {
      blob: new Blob([csv], { type: "text/csv" }),
      fileName: `${baseName}.csv`,
      mime: "text/csv",
    };
  }

  if (format === "json") {
    const json = JSON.stringify(
      template.type === "windows-events"
        ? {
            report: template.name,
            generatedAt: currentNow.toISOString(),
            description: template.desc,
            metrics: {
              windowsEvents: summary.windowsEvents,
              windowsSecurityEvents: summary.windowsSecurityEvents,
            },
            events: latestWinEvents,
            dataChecks: reportChecks,
          }
        : {
            report: template.name,
            generatedAt: currentNow.toISOString(),
            metrics: summary,
            description: template.desc,
            dataChecks: reportChecks,
            cveRecords,
          },
      null,
      2
    );

    return {
      blob: new Blob([json], { type: "application/json" }),
      fileName: `${baseName}.json`,
      mime: "application/json",
    };
  }

  const html = template.type === "windows-events"
    ? `<!doctype html>
<html><head><meta charset="utf-8"/><title>${template.name}</title></head>
<body>
<h1>${template.name}</h1>
<p>Generated: ${fmtFullDateTime(currentNow)}</p>
<p>Total Events: ${summary.windowsEvents} | Security Relevant: ${summary.windowsSecurityEvents}</p>
${reportChecks.length ? `<h2>Data Checks</h2><ul>${reportChecks.map((c) => `<li><strong>${c.label}</strong> — ${c.detail}</li>`).join("")}</ul>` : ""}
<table border="1" cellspacing="0" cellpadding="6">
<thead><tr><th>Event ID</th><th>Channel</th><th>Level</th><th>User</th><th>Computer</th><th>Message</th></tr></thead>
<tbody>
${latestWinEvents.map((e) => `<tr><td>${e.eventId || ""}</td><td>${e.channel || ""}</td><td>${e.level || ""}</td><td>${e.userName || ""}</td><td>${e.computerName || ""}</td><td>${String(e.message || "").replace(/</g, "&lt;")}</td></tr>`).join("")}
</tbody>
</table>
</body></html>`
    : `<!doctype html>
<html><head><meta charset="utf-8"/><title>${template.name}</title></head>
<body>
<h1>${template.name}</h1>
<p>Generated: ${fmtFullDateTime(currentNow)}</p>
<ul>
<li>Alerts (30d): ${summary.alerts30d}</li>
<li>Open Incidents: ${summary.openIncidents}</li>
<li>Infected Files: ${summary.infectedFiles}</li>
<li>Critical Vulnerabilities: ${summary.criticalVulns}</li>
</ul>
${reportChecks.length ? `<h2>Data Checks</h2><ul>${reportChecks.map((c) => `<li><strong>${c.label}:</strong> ${c.detail}</li>`).join("")}</ul>` : ""}
${template.type === "vulnerability" && cveRecords.length ? `<h2>CVE Records</h2><table border="1" cellspacing="0" cellpadding="6"><thead><tr><th>CVE</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Last Seen</th></tr></thead><tbody>${cveRecords.map((r) => `<tr><td>${r.cveId}</td><td>${r.totalFindings}</td><td>${r.criticalCount}</td><td>${r.highCount}</td><td>${r.mediumCount}</td><td>${r.lowCount}</td><td>${r.lastObserved || ""}</td></tr>`).join("")}</tbody></table>` : ""}
<p>${template.desc}</p>
</body></html>`;

  return {
    blob: new Blob([html], { type: "text/html" }),
    fileName: `${baseName}.html`,
    mime: "text/html",
  };
}

export default function Reports({ appState, onToast }) {
  const { alerts, incidents, malwareScans, vulnFindings } = appState;
  const [generated, setGenerated] = useState([]);
  const [generating, setGenerating] = useState(null);
  const [format, setFormat] = useState("pdf");
  const [synced30d, setSynced30d] = useState(null);
  const [syncing, setSyncing] = useState(false);
  const [lastSyncedAt, setLastSyncedAt] = useState(null);

  const refresh30dSync = async ({ silent = false } = {}) => {
    setSyncing(true);
    try {
      const payload = await reportsApi.syncData({ days: 30, limit: 2000 });
      setSynced30d(payload);
      const ts = now().toISOString();
      setLastSyncedAt(ts);
      if (!silent) onToast("30-day database data synced", "success");
      return payload;
    } catch {
      if (!silent) onToast("Failed to sync 30-day database data", "error");
      return null;
    } finally {
      setSyncing(false);
    }
  };

  useEffect(() => {
    let mounted = true;
    (async () => {
      const payload = await refresh30dSync({ silent: true });
      if (!mounted || !payload) return;
    })();
    return () => { mounted = false; };
  }, []);

  const downloadGeneratedReport = async (report) => {
    try {
      if (!report.blob) {
        onToast("No file available for this report", "warning");
        return;
      }

      try {
        const mime = report.format === "pdf"
          ? "application/pdf"
          : report.format === "csv"
            ? "text/csv"
            : report.format === "json"
              ? "application/json"
              : "text/html";
        const saved = await saveBlobWithPicker(report.blob, report.name, mime);
        if (saved) {
          onToast("Report saved: " + report.name, "success");
          return;
        }
      } catch {
        // User canceled picker or browser does not support it.
      }

      triggerBrowserDownload(report.blob, report.name);
      onToast("Downloading " + report.name, "info");
    } catch (e) {
      onToast("Download failed: " + (e.message || "unknown error"), "error");
    }
  };

  const generate = async (template) => {
    setGenerating(template.id);
    onToast(`Generating ${template.name}…`, "info");

    try {
      let reportData30d = synced30d;
      const refreshed = await refresh30dSync({ silent: true });
      if (refreshed) {
        reportData30d = refreshed;
      } else {
        onToast("Using cached data: failed to refresh 30-day database sync", "warning");
      }

      if (template.type === "vulnerability" && format === "pdf") {
        const { blob, fileName } = await reportsApi.downloadVulnerabilityPdf();
        const downloadName = fileName || `Vulnerability_Report_${fmtISODate(now())}.pdf`;

        try {
          const saved = await saveBlobWithPicker(blob, downloadName, "application/pdf");
          if (!saved) {
            triggerBrowserDownload(blob, downloadName);
          }
        } catch {
          triggerBrowserDownload(blob, downloadName);
        }

        const report = {
          id: Date.now(),
          name: downloadName,
          type: template.type,
          format,
          size: `${Math.max(1, Math.round(blob.size / 1024))} KB`,
          generatedAt: now().toISOString(),
          status: "completed",
          blob,
        };
        setGenerated(p => [report, ...p]);
        onToast(`${template.name} generated and downloaded`, "success");
        return;
      }

      const built = createMockReportBlob(template, format, appState, reportData30d);
      try {
        const saved = await saveBlobWithPicker(built.blob, built.fileName, built.mime);
        if (!saved) {
          triggerBrowserDownload(built.blob, built.fileName);
        }
      } catch {
        triggerBrowserDownload(built.blob, built.fileName);
      }

      const report = {
        id: Date.now(),
        name: built.fileName,
        type: template.type,
        format,
        size: `${Math.max(1, Math.round(built.blob.size / 1024))} KB`,
        generatedAt: now().toISOString(),
        status: "completed",
        blob: built.blob,
      };
      setGenerated(p => [report, ...p]);
      onToast(`${template.name} generated successfully`, "success");
    } catch (e) {
      onToast(`Failed to generate ${template.name}: ${e.message || "unknown error"}`, "error");
    } finally {
      setGenerating(null);
    }
  };

  const syncedSummary = synced30d?.summary || {};
  const stats = [
    { icon:"🚨", label:"Alerts (30d)",    value: syncedSummary.alerts ?? alerts.length, color:"#e11d48" },
    { icon:"🔥", label:"Open Incidents",  value: syncedSummary.openIncidents ?? incidents.filter(i=>["open","investigating"].includes(i.status)).length, color:"#f59e0b" },
    { icon:"☠",  label:"Infected Files",  value: syncedSummary.infectedFiles ?? malwareScans.filter(s=>s.scanResult==="infected").length, color:"#7c3aed" },
    { icon:"🔴", label:"Critical Vulns",  value: vulnFindings.filter(f=>f.severity==="critical").length,   color:"#2d6bff" },
  ];
  const checkItems = synced30d?.checks || [];
  const syncedCves = synced30d?.cveRecords || [];
  const statusStyles = {
    pass: { bg:"#dcfce7", text:"#166534" },
    warn: { bg:"#fee2e2", text:"#b91c1c" },
    info: { bg:"#dbeafe", text:"#1d4ed8" },
  };

  return (
    <div className="page-enter">
      {/* Quick stats for report context */}
      <Grid cols={4} gap={14} style={{ marginBottom:20 }}>
        {stats.map(s => (
          <StatCard key={s.label} icon={s.icon} label={s.label} value={s.value} color={s.color} />
        ))}
      </Grid>

      <Grid cols={2} gap={16} style={{ marginBottom:20 }}>
        <Panel title="Data Health Checks" subtitle="Ensure synced data is ready for export">
          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:12, gap:12 }}>
            <div style={{ fontSize:11, fontFamily:"var(--font-mono)", color:"var(--color-text-tertiary)" }}>
              30-day sync: {lastSyncedAt ? fmtDateTime(lastSyncedAt) : "Pending"}
            </div>
            <Btn size="xs" variant="ghost" onClick={() => refresh30dSync()} disabled={syncing}>
              {syncing ? "Refreshing..." : "Refresh Data"}
            </Btn>
          </div>
          {checkItems.length === 0 ? (
            <EmptyState icon="🧪" title="No checks yet" sub="Sync data to view readiness checks" />
          ) : (
            <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
              {checkItems.map((item) => {
                const palette = statusStyles[item.status] || statusStyles.info;
                return (
                  <div key={item.id} style={{
                    padding:"10px 12px",
                    border:"1px solid var(--color-border)",
                    borderRadius:"var(--r-md)",
                    background:"#fff",
                    boxShadow:"var(--shadow-xs)",
                  }}>
                    <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", gap:12 }}>
                      <div style={{ fontWeight:600, fontSize:13, color:"var(--color-text-primary)" }}>{item.label}</div>
                      <span style={{
                        fontSize:10,
                        fontFamily:"var(--font-mono)",
                        textTransform:"uppercase",
                        padding:"2px 8px",
                        borderRadius:999,
                        background:palette.bg,
                        color:palette.text,
                      }}>{(item.status || "info").toUpperCase()}</span>
                    </div>
                    <div style={{ fontSize:12, color:"var(--color-text-tertiary)", marginTop:4 }}>{item.detail}</div>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>

        <Panel title="Top CVE Records" subtitle="Most frequent CVE findings in sync window">
          {syncedCves.length === 0 ? (
            <EmptyState icon="📄" title="No CVE data" sub="Run vulnerability scans to populate CVE records" />
          ) : (
            <div style={{ overflowX:"auto" }}>
              <table style={{ width:"100%", borderCollapse:"collapse", fontSize:12 }}>
                <thead>
                  <tr style={{ textAlign:"left", background:"#f1f5f9", borderBottom:"1px solid #e2e8f0" }}>
                    {['CVE','Total','Critical','High','Medium','Last Seen'].map((h) => (
                      <th key={h} style={{ padding:"8px 10px", fontFamily:"var(--font-mono)", fontSize:10, color:"#475569", textTransform:"uppercase", letterSpacing:"0.05em" }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {syncedCves.slice(0,5).map((record) => (
                    <tr key={record.cveId} style={{ borderBottom:"1px solid #f1f5f9" }}>
                      <td style={{ padding:"8px 10px", fontFamily:"var(--font-mono)", color:"#0f172a" }}>{record.cveId}</td>
                      <td style={{ padding:"8px 10px" }}>{record.totalFindings}</td>
                      <td style={{ padding:"8px 10px", color:"#b91c1c" }}>{record.criticalCount}</td>
                      <td style={{ padding:"8px 10px", color:"#ea580c" }}>{record.highCount}</td>
                      <td style={{ padding:"8px 10px", color:"#ca8a04" }}>{record.mediumCount}</td>
                      <td style={{ padding:"8px 10px", color:"#475569" }}>{record.lastObserved ? fmtDateTime(record.lastObserved) : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </Grid>

      <Grid cols={2} gap={16}>
        {/* Templates */}
        <Panel title="Report Templates" subtitle="Click Generate to create a report">
          <div style={{ padding:"0 4px" }}>
            {/* Format selector */}
            <div style={{ padding:"12px 14px 0", marginBottom:4 }}>
              <div style={{ fontSize:11, fontFamily:"var(--font-mono)", color:"var(--color-text-tertiary)",
                textTransform:"uppercase", letterSpacing:"0.05em", marginBottom:8, fontWeight:600 }}>Output Format</div>
              <div style={{ display:"flex", gap:8 }}>
                {["pdf","html","csv","json"].map(f => {
                  const fc = FORMAT_COLORS[f];
                  return (
                    <button key={f} onClick={() => setFormat(f)} style={{
                      padding:"4px 12px", borderRadius:99, border:`1.5px solid ${format===f ? fc.text : "#e2e8f0"}`,
                      background: format===f ? fc.bg : "transparent",
                      color: format===f ? fc.text : "var(--color-text-tertiary)",
                      fontFamily:"var(--font-mono)", fontSize:11, fontWeight:700, cursor:"pointer",
                      textTransform:"uppercase", transition:"all 0.14s",
                    }}>{f}</button>
                  );
                })}
              </div>
            </div>

            {TEMPLATES.map(t => (
              <div key={t.id} style={{
                display:"flex", alignItems:"center", justifyContent:"space-between",
                padding:"14px 14px", borderTop:"1.5px solid var(--color-border)",
              }}
                onMouseEnter={e => e.currentTarget.style.background = "#f8fafc"}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
              >
                <div style={{ display:"flex", gap:12, alignItems:"flex-start", flex:1 }}>
                  <div style={{
                    width:36, height:36, borderRadius:"var(--r-md)", background:"#f0f5ff",
                    border:"1.5px solid #c1d4ff", display:"flex", alignItems:"center",
                    justifyContent:"center", fontSize:18, flexShrink:0,
                  }}><ReportTemplateIcon type={t.icon} /></div>
                  <div style={{ flex:1 }}>
                    <div style={{ fontWeight:700, fontSize:13, color:"var(--color-text-primary)", marginBottom:2 }}>{t.name}</div>
                    <div style={{ fontSize:12, color:"var(--color-text-tertiary)", lineHeight:1.4 }}>{t.desc}</div>
                  </div>
                </div>
                <Btn size="sm" variant={generating===t.id ? "ghost" : "outline"}
                  disabled={generating===t.id}
                  onClick={() => generate(t)}
                  style={{ marginLeft:12, flexShrink:0 }}>
                  {generating===t.id
                    ? <><span style={{ display:"inline-block", animation:"spin 1s linear infinite" }}>⟳</span> Generating…</>
                    : "Generate"}
                </Btn>
              </div>
            ))}
          </div>
        </Panel>

        {/* Generated Reports */}
        <Panel title="Generated Reports" subtitle="Download or share reports">
          {generated.length === 0 ? (
            <EmptyState icon="📂" title="No reports generated yet"
              sub="Select a template and click Generate to create your first report" />
          ) : (
            <div>
              {generated.map(r => {
                const fc = FORMAT_COLORS[r.format] || FORMAT_COLORS.pdf;
                return (
                  <div key={r.id} style={{
                    display:"flex", alignItems:"center", justifyContent:"space-between",
                    padding:"12px 16px", borderBottom:"1px solid #f1f5f9",
                  }}>
                    <div style={{ display:"flex", gap:10, alignItems:"center", flex:1, minWidth:0 }}>
                      <div style={{
                        width:32, height:32, borderRadius:"var(--r-md)",
                        background:fc.bg, border:`1.5px solid ${fc.border}`,
                        display:"flex", alignItems:"center", justifyContent:"center",
                        fontFamily:"var(--font-mono)", fontSize:10, fontWeight:700,
                        color:fc.text, flexShrink:0,
                      }}>{r.format.toUpperCase()}</div>
                      <div style={{ minWidth:0 }}>
                        <div style={{ fontWeight:600, fontSize:13, color:"var(--color-text-primary)",
                          overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{r.name}</div>
                        <div style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--color-text-tertiary)", marginTop:1 }}>
                          {r.size} · {fmtDateTime(r.generatedAt)}
                        </div>
                      </div>
                    </div>
                    <div style={{ display:"flex", gap:6, flexShrink:0, marginLeft:10 }}>
                      <Btn size="xs" variant="ghost" onClick={() => downloadGeneratedReport(r)}>⬇ Download</Btn>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>
      </Grid>

      {/* Scheduled Reports */}
      <div style={{ marginTop:20 }}>
        <Panel title="Scheduled Reports" subtitle="Automated report delivery configuration">
          <div style={{ padding:"20px 16px" }}>
            {[
              { name:"Daily Security Digest",   schedule:"Every day at 08:00",  recipients:"admin@kavachopsai.local",    active:true  },
              { name:"Weekly Compliance Report", schedule:"Every Monday at 09:00",recipients:"auditor1@kavachopsai.local", active:true  },
              { name:"Monthly Executive Summary",schedule:"1st of month at 07:00",recipients:"admin@kavachopsai.local",   active:false },
            ].map((s, i) => (
              <div key={i} style={{
                display:"flex", alignItems:"center", justifyContent:"space-between",
                padding:"12px 14px",
                background: i % 2 === 0 ? "#fafbfd" : "transparent",
                borderRadius:"var(--r-md)", marginBottom:4,
              }}>
                <div style={{ display:"flex", gap:12, alignItems:"center" }}>
                  <span style={{
                    width:8, height:8, borderRadius:"50%", flexShrink:0,
                    background: s.active ? "#10b981" : "#94a3b8",
                    animation: s.active ? "pulseDot 2s ease-in-out infinite" : "none",
                    display:"inline-block",
                  }} />
                  <div>
                    <div style={{ fontWeight:600, fontSize:13, color:"var(--color-text-primary)" }}>{s.name}</div>
                    <div style={{ fontSize:11, color:"var(--color-text-tertiary)", marginTop:1 }}>
                      {s.schedule} · To: {s.recipients}
                    </div>
                  </div>
                </div>
                <div style={{ display:"flex", gap:8, alignItems:"center" }}>
                  <Badge status={s.active ? "active" : "inactive"} size="xs" />
                  <Btn size="xs" variant="ghost" onClick={() => onToast("Schedule updated", "success")}>
                    {s.active ? "Pause" : "Enable"}
                  </Btn>
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}
