import { useState } from "react";
import { severityConfig, statusConfig } from "../design-system.js";

// ── Badge ───────────────────────────────────────────────────────
export function Badge({ label, severity, status, size = "sm" }) {
  const cfg = severity
    ? severityConfig(severity)
    : status
    ? statusConfig(status)
    : { bg: "#f1f5f9", border: "#e2e8f0", text: "#475569" };
  const pad = size === "xs" ? "2px 7px" : size === "lg" ? "5px 12px" : "3px 9px";
  const fs  = size === "xs" ? 10 : size === "lg" ? 13 : 11;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 5,
      padding: pad, borderRadius: 99, fontSize: fs, fontWeight: 600,
      fontFamily: "var(--font-mono)", letterSpacing: "0.02em",
      background: cfg.bg, border: `1.5px solid ${cfg.border}`, color: cfg.text,
      whiteSpace: "nowrap",
    }}>
      {cfg.dot && (
        <span style={{
          width: 5, height: 5, borderRadius: "50%",
          background: cfg.dot, flexShrink: 0,
          animation: "pulseDot 2s ease-in-out infinite",
          display: "inline-block",
        }} />
      )}
      {label || severity || status}
    </span>
  );
}

// ── Button ──────────────────────────────────────────────────────
export function Btn({ children, onClick, variant = "ghost", size = "md", disabled, style = {} }) {
  const [hov, setHov] = useState(false);
  const base = {
    display: "inline-flex", alignItems: "center", gap: 6, cursor: disabled ? "not-allowed" : "pointer",
    fontFamily: "var(--font-body)", fontWeight: 600, borderRadius: "var(--r-md)",
    transition: "all 0.14s", border: "1.5px solid transparent", outline: "none",
    opacity: disabled ? 0.5 : 1, ...style,
  };
  const sizes = { xs:"6px 10px;font-size:11px", sm:"7px 12px;font-size:12px", md:"8px 16px;font-size:13px", lg:"10px 20px;font-size:14px" };
  const [p, fs] = (sizes[size] || sizes.md).split(";font-size:");
  const variants = {
    primary: { background: hov ? "#1a52e0" : "#2d6bff", color: "#fff", borderColor: hov ? "#1a52e0" : "#2d6bff" },
    danger:  { background: hov ? "#fee2e2" : "#fff1f2", color: "#be123c", borderColor: "#fecdd3" },
    success: { background: hov ? "#d1fae5" : "#ecfdf5", color: "#047857", borderColor: "#a7f3d0" },
    ghost:   { background: hov ? "#f1f5f9" : "transparent", color: "#334155", borderColor: "#e2e8f0" },
    amber:   { background: hov ? "#fef3c7" : "#fffbeb", color: "#b45309", borderColor: "#fde68a" },
    outline: { background: hov ? "#f0f5ff" : "transparent", color: "#2d6bff", borderColor: "#c1d4ff" },
  };
  return (
    <button
      style={{ ...base, padding: p, fontSize: fs, ...variants[variant] }}
      onClick={onClick} disabled={disabled}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
    >{children}</button>
  );
}

// ── Card ────────────────────────────────────────────────────────
export function Card({ children, style = {}, padding = "20px", hover = false }) {
  const [hov, setHov] = useState(false);
  return (
    <div
      style={{
        background: "var(--color-surface)",
        border: "1.5px solid var(--color-border)",
        borderRadius: "var(--r-lg)", padding,
        boxShadow: hov && hover ? "var(--shadow-md)" : "var(--shadow-xs)",
        transition: "box-shadow 0.2s, border-color 0.2s",
        borderColor: hov && hover ? "#c1d4ff" : "var(--color-border)",
        ...style,
      }}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
    >{children}</div>
  );
}

function StatCardIcon({ label }) {
  const icons = {
    "Active Alerts": <><path d="M6 17h12l-1.2-1.8V10a4.8 4.8 0 0 0-9.6 0v5.2L6 17Z" /><path d="M10 20h4" /></>,
    "Open Incidents": <path d="m12 3 2.3 5.1 5.7.7-4.2 4 1.1 5.7-4.9-2.7-4.9 2.7 1.1-5.7-4.2-4 5.7-.7L12 3Z" />,
    "Packets Captured": <><path d="m7 7 5-3 5 3-5 3-5-3Z" /><path d="m7 12 5 3 5-3M7 17l5 3 5-3" /><path d="M12 10v5" /></>,
    "Total Alerts": <><path d="M6 17h12l-1.2-1.8V10a4.8 4.8 0 0 0-9.6 0v5.2L6 17Z" /><path d="M10 20h4M12 3v2" /><circle cx="18" cy="6" r="2.2" /></>,
    "Critical/High": <><path d="M12 3 20 7v5c0 4.5-3.1 7.6-8 9-4.9-1.4-8-4.5-8-9V7l8-4Z" /><path d="M12 8v5M12 16h.01" strokeWidth="2.2" /></>,
    "Active Rules": <><path d="M5 6h14M5 12h14M5 18h14" /><circle cx="9" cy="6" r="2" fill="currentColor" /><circle cx="15" cy="12" r="2" fill="currentColor" /><circle cx="11" cy="18" r="2" fill="currentColor" /></>,
    "Active Traps": <><path d="M8 4h8M9 4v4l-3 7a3 3 0 0 0 3 4h6a3 3 0 0 0 3-4l-3-7V4" /><path d="M8 14h8" /></>,
    "Interactions (24h)": <><path d="M4 12h4l2-6 4 12 2-6h4" /></>,
    "Unique Attackers": <><circle cx="12" cy="8" r="3" /><path d="M5 20a7 7 0 0 1 14 0" /></>,
    "Critical Threats": <><circle cx="12" cy="12" r="7" /><path d="M12 8v5M12 16h.01" strokeWidth="2.2" /></>,
    "Open": <><path d="M5 8h14v11H5z" /><path d="M8 8V6a4 4 0 0 1 8 0v2M9 13h6" /></>,
    "Investigating": <><circle cx="10.5" cy="10.5" r="6" /><path d="m15 15 5 5" /></>,
    "Contained": <><path d="M12 3 20 7v5c0 4.5-3.1 7.6-8 9-4.9-1.4-8-4.5-8-9V7l8-4Z" /><path d="m9 12 2 2 4-4" /></>,
    "Resolved": <><circle cx="12" cy="12" r="8" /><path d="m8 12 2.5 2.5L16 9" /></>,
    "Infected": <><path d="M8 8.5a4 4 0 0 1 8 0v7a4 4 0 0 1-8 0z" /><path d="M6 10H3M6 14H4M18 10h3M18 14h2M9 5 8 3M15 5l1-2" /></>,
    "Suspicious": <><path d="m12 3 9 17H3L12 3Z" /><path d="M12 9v5M12 17h.01" strokeWidth="2.2" /></>,
    "Clean": <><path d="M12 3 20 7v5c0 4.5-3.1 7.6-8 9-4.9-1.4-8-4.5-8-9V7l8-4Z" /><path d="m9 12 2 2 4-4" /></>,
    "Quarantined": <><rect x="5" y="4" width="14" height="16" rx="2" /><path d="M9 4v4h6V4M9 13h6M9 16h4" /></>,
    "Total Users": <><circle cx="9" cy="8" r="3" /><path d="M3 20a6 6 0 0 1 12 0M16 11a3 3 0 1 0 0-6M17 14a5 5 0 0 1 4 6" /></>,
    "Active Users": <><circle cx="10" cy="8" r="3" /><path d="M4 20a6 6 0 0 1 12 0M16 14l2 2 3-4" /></>,
    "Administrators": <><path d="M12 3 20 7v5c0 4.5-3.1 7.6-8 9-4.9-1.4-8-4.5-8-9V7l8-4Z" /><path d="M12 8v5M9.5 10.5h5" /></>,
    "Analysts": <><path d="M5 19V9M12 19V5M19 19v-7" /><path d="M3 19h18" /></>,
    "Critical": <><path d="m12 3 9 17H3L12 3Z" /><path d="M12 9v5M12 17h.01" strokeWidth="2.2" /></>,
    "High": <><path d="m12 3 9 17H3L12 3Z" /><path d="M12 9v5M12 17h.01" strokeWidth="2.2" /></>,
    "Medium": <><circle cx="12" cy="12" r="8" /><path d="M12 8v5M12 16h.01" strokeWidth="2.2" /></>,
    "Low / Info": <><circle cx="12" cy="12" r="8" /><path d="M9 12h6" /></>,
    "Total Events (24h)": <><rect x="4" y="5" width="16" height="15" rx="2" /><path d="M8 3v4M16 3v4M4 10h16M8 14h3M8 17h6" /></>,
    "Failed Logins": <><rect x="4" y="10" width="16" height="10" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3" /></>,
    "Critical Events": <><path d="m12 3 9 17H3L12 3Z" /><path d="M12 9v5M12 17h.01" strokeWidth="2.2" /></>,
    "Alerts (30d)": <><path d="M6 17h12l-1.2-1.8V10a4.8 4.8 0 0 0-9.6 0v5.2L6 17Z" /><path d="M10 20h4M12 3v2" /></>,
    "Infected Files": <><path d="M8 8.5a4 4 0 0 1 8 0v7a4 4 0 0 1-8 0z" /><path d="M6 10H3M6 14H4M18 10h3M18 14h2M9 5 8 3M15 5l1-2" /></>,
    "Critical Vulns": <><path d="m12 3 9 17H3L12 3Z" /><path d="M12 9v5M12 17h.01" strokeWidth="2.2" /></>,
    "Security Events": <><rect x="4" y="4" width="16" height="16" rx="2" /><path d="M8 8h8M8 12h8M8 16h5" /></>,
  };
  return (
    <svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {icons[label] || <circle cx="12" cy="12" r="7" />}
    </svg>
  );
}

// ── StatCard ────────────────────────────────────────────────────
export function StatCard({ icon, label, value, sub, color = "#2d6bff", trend, onClick }) {
  const [hov, setHov] = useState(false);
  return (
    <div
      style={{
        background: `linear-gradient(135deg, #ffffff 0%, ${color}14 100%)`,
        border: "1.5px solid var(--color-border)",
        borderRadius: "var(--r-lg)", padding: "18px 20px",
        boxShadow: hov ? `0 10px 24px ${color}18` : "var(--shadow-xs)",
        borderColor: hov ? color + "66" : color + "38",
        transition: "all 0.18s", cursor: onClick ? "pointer" : "default",
        position: "relative", overflow: "hidden",
      }}
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
    >
      <div style={{
        position: "absolute", top: 0, left: 0, right: 0, height: 3,
        background: `linear-gradient(90deg, transparent 0%, ${color}40 50%, transparent 100%)`,
        opacity: hov ? 1 : 0.5, transition: "opacity 0.2s",
      }} />
      <div style={{
        position: "absolute", width: 110, height: 110, right: -48, top: -48,
        borderRadius: "50%", background: `${color}14`, pointerEvents: "none",
      }} />
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
        <div style={{
          width: 36, height: 36, borderRadius: "var(--r-md)",
          background: `linear-gradient(145deg, ${color}2e, ${color}16)`,
          border: `1px solid ${color}4d`,
          boxShadow: `0 4px 10px ${color}18`,
          display: "flex", alignItems: "center", justifyContent: "center",
          fontSize: 17, lineHeight: 1, color,
        }}><StatCardIcon label={label} /></div>
        {trend && (
          <span style={{ fontSize: 11, fontWeight: 600, color: trend > 0 ? "#e11d48" : "#059669",
            fontFamily: "var(--font-mono)" }}>
            {trend > 0 ? "↑" : "↓"} {Math.abs(trend)}%
          </span>
        )}
      </div>
      <div style={{ fontSize: 11, color: "var(--color-text-tertiary)", fontWeight: 600,
        letterSpacing: "0.05em", textTransform: "uppercase", marginBottom: 4,
        fontFamily: "var(--font-mono)" }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700, color, fontFamily: "var(--font-display)",
        lineHeight: 1.1, letterSpacing: "-0.02em" }}>{value}</div>
      {sub && <div style={{ fontSize: 11, color: "var(--color-text-tertiary)", marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

// ── Section Header ───────────────────────────────────────────────
export function SectionHeader({ title, sub, action, icon }) {
  return (
    <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 20 }}>
      <div>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
          {icon && <span style={{ fontSize: 20 }}>{icon}</span>}
          <h2 style={{ fontFamily: "var(--font-display)", fontSize: 20, fontWeight: 700,
            color: "var(--color-text-primary)", letterSpacing: "-0.02em" }}>{title}</h2>
        </div>
        {sub && <p style={{ fontSize: 13, color: "var(--color-text-secondary)", marginLeft: icon ? 30 : 0 }}>{sub}</p>}
      </div>
      {action && <div style={{ flexShrink: 0 }}>{action}</div>}
    </div>
  );
}

function inferPanelAccent(title) {
  const text = String(title || "").toLowerCase();
  if (/network|traffic|packet|ids/.test(text)) return "#2563eb";
  if (/event|windows|log/.test(text)) return "#0f766e";
  if (/malware|scan|quarantine/.test(text)) return "#16a34a";
  if (/incident|alert|threat/.test(text)) return "#e11d48";
  if (/vuln|cve|risk/.test(text)) return "#d97706";
  if (/honey|attacker/.test(text)) return "#9333ea";
  if (/report|compliance|executive/.test(text)) return "#0891b2";
  return "#2d6bff";
}

// ── Panel ────────────────────────────────────────────────────────
export function Panel({ title, subtitle, actions, children, padding = "0", accent }) {
  const panelAccent = accent || inferPanelAccent(title);
  return (
    <Card padding="0" style={panelAccent ? {
      borderColor: `${panelAccent}35`,
      boxShadow: `0 4px 14px ${panelAccent}10`,
      background: `linear-gradient(135deg, #ffffff 0%, ${panelAccent}08 100%)`,
    } : {}}>
      {(title || actions) && (
        <div style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "14px 18px", borderBottom: "1.5px solid var(--color-border)",
          background: `linear-gradient(135deg, #ffffff 0%, ${panelAccent}0d 100%)`,
          borderTop: `3px solid ${panelAccent}70`,
        }}>
          <div>
            <div style={{ fontFamily: "var(--font-display)", fontWeight: 700, fontSize: 13,
              color: "var(--color-text-primary)", letterSpacing: "-0.01em" }}>{title}</div>
            {subtitle && <div style={{ fontSize: 11, color: "var(--color-text-tertiary)", marginTop: 1 }}>{subtitle}</div>}
          </div>
          {actions && <div style={{ display: "flex", gap: 8, alignItems: "center" }}>{actions}</div>}
        </div>
      )}
      <div style={{ padding }}>{children}</div>
    </Card>
  );
}

// ── Data Table ───────────────────────────────────────────────────
export function DataTable({ columns, rows, emptyText = "No data found" }) {
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
        <thead>
          <tr style={{ background: "#fafbfd", borderBottom: "1.5px solid var(--color-border)" }}>
            {columns.map((col, i) => (
              <th key={i} style={{
                textAlign: "left", padding: "10px 14px",
                fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 600,
                color: "var(--color-text-tertiary)", letterSpacing: "0.06em",
                textTransform: "uppercase", whiteSpace: "nowrap",
              }}>{col.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td colSpan={columns.length} style={{ textAlign: "center", padding: "40px 16px",
                color: "var(--color-text-tertiary)", fontSize: 13 }}>{emptyText}</td>
            </tr>
          ) : (
            rows.map((row, i) => (
              <tr key={i} style={{ borderBottom: "1px solid #f1f5f9", transition: "background 0.1s" }}
                onMouseEnter={e => e.currentTarget.style.background = "#f8fafc"}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
              >
                {columns.map((col, j) => (
                  <td key={j} style={{ padding: "10px 14px", verticalAlign: "middle",
                    fontFamily: col.mono ? "var(--font-mono)" : "var(--font-body)",
                    fontSize: col.mono ? 11 : 13, color: col.dim ? "var(--color-text-secondary)" : "var(--color-text-primary)",
                    maxWidth: col.maxWidth || "none", overflow: "hidden",
                    textOverflow: "ellipsis", whiteSpace: col.wrap ? "normal" : "nowrap",
                  }}>
                    {col.render ? col.render(row) : row[col.key]}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

// ── Modal ────────────────────────────────────────────────────────
export function Modal({ open, onClose, title, children, footer, width = 520 }) {
  if (!open) return null;
  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 999,
      background: "rgba(15,23,42,0.45)", backdropFilter: "blur(6px)",
      display: "flex", alignItems: "center", justifyContent: "center", padding: 20,
    }} onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div style={{
        background: "var(--color-surface)", borderRadius: "var(--r-xl)",
        width, maxWidth: "95vw", maxHeight: "88vh", overflow: "auto",
        boxShadow: "0 24px 48px rgba(15,23,42,0.18), 0 8px 16px rgba(15,23,42,0.1)",
        border: "1.5px solid var(--color-border)", animation: "fadeUp 0.2s ease",
      }}>
        <div style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "18px 22px", borderBottom: "1.5px solid var(--color-border)",
          background: "#fafbfd",
        }}>
          <h3 style={{ fontFamily: "var(--font-display)", fontWeight: 700, fontSize: 15,
            color: "var(--color-text-primary)", letterSpacing: "-0.02em" }}>{title}</h3>
          <button onClick={onClose} style={{
            background: "none", border: "none", fontSize: 20, cursor: "pointer",
            color: "var(--color-text-tertiary)", lineHeight: 1, padding: "2px 6px",
            borderRadius: "var(--r-sm)", transition: "all 0.12s",
          }}
            onMouseEnter={e => { e.target.style.background = "#fee2e2"; e.target.style.color = "#e11d48"; }}
            onMouseLeave={e => { e.target.style.background = "none"; e.target.style.color = "var(--color-text-tertiary)"; }}
          >×</button>
        </div>
        <div style={{ padding: "22px" }}>{children}</div>
        {footer && (
          <div style={{ padding: "14px 22px", borderTop: "1.5px solid var(--color-border)",
            display: "flex", justifyContent: "flex-end", gap: 10, background: "#fafbfd",
          }}>{footer}</div>
        )}
      </div>
    </div>
  );
}

// ── Form Group ───────────────────────────────────────────────────
export function FormGroup({ label, children, hint }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <label style={{ display: "block", fontFamily: "var(--font-mono)", fontSize: 11,
        fontWeight: 600, color: "var(--color-text-secondary)", letterSpacing: "0.05em",
        textTransform: "uppercase", marginBottom: 6 }}>{label}</label>
      {children}
      {hint && <div style={{ fontSize: 11, color: "var(--color-text-tertiary)", marginTop: 4 }}>{hint}</div>}
    </div>
  );
}

// ── Grid ────────────────────────────────────────────────────────
export function Grid({ cols = 2, gap = 16, children, style = {} }) {
  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: `repeat(${cols}, minmax(0, 1fr))`,
      gap, ...style,
    }}>{children}</div>
  );
}

// ── Chip / Tag ───────────────────────────────────────────────────
export function Chip({ label, color = "#2d6bff" }) {
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", padding: "2px 8px",
      borderRadius: 99, fontSize: 11, fontWeight: 600,
      fontFamily: "var(--font-mono)", background: color + "15",
      color, border: `1px solid ${color}30`, whiteSpace: "nowrap",
    }}>{label}</span>
  );
}

// ── IP Pill ──────────────────────────────────────────────────────
export function IPPill({ ip }) {
  return (
    <span style={{
      fontFamily: "var(--font-mono)", fontSize: 11,
      background: "#f0f5ff", border: "1px solid #c1d4ff",
      color: "#1340b8", padding: "2px 8px", borderRadius: "var(--r-sm)",
      whiteSpace: "nowrap",
    }}>{ip}</span>
  );
}

// ── Live Feed Item ───────────────────────────────────────────────
export function FeedItem({ time, severity, badgeLabel, message, type }) {
  const sev = severity?.toLowerCase() || "low";
  const dotColors = { critical: "#f43f5e", high: "#f59e0b", medium: "#8b5cf6", low: "#10b981", info: "#0ea5e9" };
  return (
    <div style={{
      display: "flex", alignItems: "flex-start", gap: 10,
      padding: "7px 12px", borderBottom: "1px solid #f1f5f9",
      animation: "slideIn 0.2s ease",
    }}>
      <span style={{
        fontFamily: "var(--font-mono)", fontSize: 10,
        color: "var(--color-text-tertiary)", minWidth: 60, marginTop: 1,
        flexShrink: 0,
      }}>{time}</span>
      <span style={{
        width: 7, height: 7, borderRadius: "50%", flexShrink: 0,
        background: dotColors[sev] || "#94a3b8", marginTop: 5,
      }} />
      <Badge label={badgeLabel} status={type === "badge" ? badgeLabel.toLowerCase() : undefined}
        severity={type === "sev" ? severity : undefined} size="xs" />
      <span style={{ fontSize: 12, color: "var(--color-text-secondary)", lineHeight: 1.5 }}>{message}</span>
    </div>
  );
}

// ── Toggle ───────────────────────────────────────────────────────
export function Toggle({ value, onChange }) {
  return (
    <div
      onClick={() => onChange(!value)}
      style={{
        width: 38, height: 22, borderRadius: 99, cursor: "pointer",
        background: value ? "#2d6bff" : "#e2e8f0",
        position: "relative", transition: "background 0.2s", flexShrink: 0,
        border: `1.5px solid ${value ? "#1a52e0" : "#cbd5e1"}`,
      }}
    >
      <div style={{
        width: 16, height: 16, borderRadius: "50%", background: "#fff",
        position: "absolute", top: "50%", transform: "translateY(-50%)",
        left: value ? 18 : 2, transition: "left 0.2s",
        boxShadow: "0 1px 3px rgba(0,0,0,0.2)",
      }} />
    </div>
  );
}

// ── Progress Bar ─────────────────────────────────────────────────
export function ProgressBar({ value, max = 100, color = "#2d6bff", height = 6 }) {
  const pct = Math.min(100, max > 0 ? (value / max) * 100 : 0);
  return (
    <div style={{ height, background: "#f1f5f9", borderRadius: 99, overflow: "hidden" }}>
      <div style={{
        height: "100%", width: `${pct}%`, background: color,
        borderRadius: 99, transition: "width 0.5s ease",
      }} />
    </div>
  );
}

// ── Empty State ──────────────────────────────────────────────────
function EmptyStateIcon({ icon }) {
  const common = {
    width: 34, height: 34, viewBox: "0 0 24 24", fill: "none",
    stroke: "currentColor", strokeWidth: 1.7, strokeLinecap: "round", strokeLinejoin: "round",
    "aria-hidden": true,
  };
  if (icon === "events") return <svg {...common}><rect x="4" y="4" width="16" height="16" rx="2" /><path d="M8 8h8M8 12h8M8 16h5" /></svg>;
  if (icon === "analytics") return <svg {...common}><path d="M5 19V9M12 19V5M19 19v-7" /><path d="M3 19h18" /><path d="m5 7 4-3 4 2 5-4" /></svg>;
  if (icon === "honeypot") return <svg {...common}><path d="M8 4h8M9 4v4l-3 7a3 3 0 0 0 3 4h6a3 3 0 0 0 3-4l-3-7V4" /><path d="M8 14h8" /></svg>;
  return <svg {...common}><path d="M4 5h16v14H4z" /><path d="M8 9h8M8 13h5" /></svg>;
}

export function EmptyState({ icon = "default", title, sub }) {
  return (
    <div style={{ textAlign: "center", padding: "40px 20px", color: "var(--color-text-tertiary)" }}>
      <div style={{ marginBottom: 10, display: "flex", justifyContent: "center" }}><EmptyStateIcon icon={icon} /></div>
      <div style={{ fontWeight: 600, fontSize: 14, color: "var(--color-text-secondary)", marginBottom: 4 }}>{title}</div>
      {sub && <div style={{ fontSize: 12 }}>{sub}</div>}
    </div>
  );
}

// ── Live Pulse ───────────────────────────────────────────────────
export function LivePulse({ active = true, label }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
      <span style={{
        width: 7, height: 7, borderRadius: "50%", flexShrink: 0,
        background: active ? "#10b981" : "#94a3b8",
        animation: active ? "pulseDot 2s ease-in-out infinite" : "none",
        display: "inline-block",
      }} />
      {label && <span style={{ fontSize: 11, fontFamily: "var(--font-mono)", fontWeight: 600,
        color: active ? "#047857" : "var(--color-text-tertiary)" }}>{label}</span>}
    </div>
  );
}

// ── Section Divider ──────────────────────────────────────────────
export function Divider({ style = {} }) {
  return <div style={{ height: "1.5px", background: "var(--color-border)", ...style }} />;
}

// ── Tooltip wrapper (simple title fallback) ───────────────────────
export function Tooltip({ tip, children }) {
  return <span title={tip}>{children}</span>;
}

// ── Select ───────────────────────────────────────────────────────
export function Select({ value, onChange, options, style = {} }) {
  return (
    <select value={value} onChange={e => onChange(e.target.value)}
      style={{ width: "auto", padding: "6px 10px", fontSize: 12, ...style }}>
      {options.map(o => (
        <option key={o.value} value={o.value}>{o.label}</option>
      ))}
    </select>
  );
}

// ── Info Row (label: value) ───────────────────────────────────────
export function InfoRow({ label, value, mono }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center",
      padding: "8px 0", borderBottom: "1px solid #f1f5f9" }}>
      <span style={{ fontSize: 12, color: "var(--color-text-secondary)", fontWeight: 500 }}>{label}</span>
      <span style={{ fontSize: 12, fontFamily: mono ? "var(--font-mono)" : "var(--font-body)",
        color: "var(--color-text-primary)", fontWeight: 500 }}>{value}</span>
    </div>
  );
}

// ── Breadcrumb ───────────────────────────────────────────────────
export function Breadcrumb({ items }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12,
      fontFamily: "var(--font-mono)", color: "var(--color-text-tertiary)" }}>
      {items.map((item, i) => (
        <span key={i} style={{ display: "flex", alignItems: "center", gap: 6 }}>
          {i > 0 && <span>/</span>}
          <span style={{ color: i === items.length - 1 ? "var(--color-text-secondary)" : "var(--color-text-tertiary)" }}>
            {item}
          </span>
        </span>
      ))}
    </div>
  );
}
