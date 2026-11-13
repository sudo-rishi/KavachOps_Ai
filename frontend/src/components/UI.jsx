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
        background: "var(--color-surface)", border: "1.5px solid var(--color-border)",
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

// ── StatCard ────────────────────────────────────────────────────
export function StatCard({ icon, label, value, sub, color = "#2d6bff", trend, onClick }) {
  const [hov, setHov] = useState(false);
  return (
    <div
      style={{
        background: "var(--color-surface)", border: "1.5px solid var(--color-border)",
        borderRadius: "var(--r-lg)", padding: "18px 20px",
        boxShadow: hov ? "var(--shadow-md)" : "var(--shadow-xs)",
        borderColor: hov ? color + "55" : "var(--color-border)",
        transition: "all 0.18s", cursor: onClick ? "pointer" : "default",
        position: "relative", overflow: "hidden",
      }}
      onClick={onClick}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
    >
      <div style={{
        position: "absolute", bottom: 0, left: 0, right: 0, height: 3,
        background: `linear-gradient(90deg, transparent 0%, ${color}40 50%, transparent 100%)`,
        opacity: hov ? 1 : 0.5, transition: "opacity 0.2s",
      }} />
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
        <div style={{
          width: 36, height: 36, borderRadius: "var(--r-md)",
          background: color + "18", display: "flex", alignItems: "center", justifyContent: "center",
          fontSize: 18,
        }}>{icon}</div>
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

// ── Panel ────────────────────────────────────────────────────────
export function Panel({ title, subtitle, actions, children, padding = "0" }) {
  return (
    <Card padding="0">
      {(title || actions) && (
        <div style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "14px 18px", borderBottom: "1.5px solid var(--color-border)",
          background: "#fafbfd",
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
export function EmptyState({ icon = "📭", title, sub }) {
  return (
    <div style={{ textAlign: "center", padding: "40px 20px", color: "var(--color-text-tertiary)" }}>
      <div style={{ fontSize: 32, marginBottom: 10 }}>{icon}</div>
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
