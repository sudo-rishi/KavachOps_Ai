import { useEffect } from "react";

const TOAST_STYLES = {
  success: { bg:"#ecfdf5", border:"#a7f3d0", text:"#047857", icon:"✓" },
  error:   { bg:"#fff1f2", border:"#fecdd3", text:"#be123c", icon:"✕" },
  warning: { bg:"#fffbeb", border:"#fde68a", text:"#b45309", icon:"⚠" },
  info:    { bg:"#f0f9ff", border:"#bae6fd", text:"#0369a1", icon:"ℹ" },
  critical:{ bg:"#fff1f2", border:"#fb7185", text:"#be123c", icon:"🚨" },
};

function ToastItem({ toast, onRemove }) {
  useEffect(() => {
    const t = setTimeout(() => onRemove(toast.id), toast.type === "critical" ? 6000 : 3500);
    return () => clearTimeout(t);
  }, [toast.id]);

  const s = TOAST_STYLES[toast.type] || TOAST_STYLES.info;

  return (
    <div style={{
      display:"flex", alignItems:"flex-start", gap:10,
      background: s.bg, border:`1.5px solid ${s.border}`,
      borderRadius:"var(--r-lg)", padding:"12px 14px",
      maxWidth:340, boxShadow:"var(--shadow-lg)",
      animation:"fadeUp 0.25s ease",
      fontFamily:"var(--font-body)",
    }}>
      <span style={{ fontSize:14, flexShrink:0, marginTop:1 }}>{s.icon}</span>
      <span style={{ fontSize:13, color:s.text, lineHeight:1.5, flex:1 }}>{toast.message}</span>
      <button onClick={() => onRemove(toast.id)} style={{
        background:"none", border:"none", cursor:"pointer",
        color:s.text, opacity:0.6, fontSize:16, lineHeight:1,
        padding:0, flexShrink:0,
      }}>×</button>
    </div>
  );
}

export default function ToastContainer({ toasts, onRemove }) {
  return (
    <div style={{
      position:"fixed", top:70, right:20, zIndex:9999,
      display:"flex", flexDirection:"column", gap:8,
      pointerEvents:"none",
    }}>
      {toasts.map(t => (
        <div key={t.id} style={{ pointerEvents:"all" }}>
          <ToastItem toast={t} onRemove={onRemove} />
        </div>
      ))}
    </div>
  );
}
