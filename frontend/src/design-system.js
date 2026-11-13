// KavachOps AI Design System
// Light professional SOC theme with restrained blue/teal accents.

export const colors = {
  primary:  { 50:'#f0f5ff', 100:'#e0eaff', 200:'#c1d4ff', 300:'#93b4ff', 400:'#5b8eff', 500:'#2d6bff', 600:'#1a52e0', 700:'#1340b8', 800:'#0f308f', 900:'#0b2270' },
  slate:    { 50:'#f8fafc', 100:'#f1f5f9', 200:'#e2e8f0', 300:'#cbd5e1', 400:'#94a3b8', 500:'#64748b', 600:'#475569', 700:'#334155', 800:'#1e293b', 900:'#0f172a' },
  red:      { 50:'#fff1f2', 100:'#ffe4e6', 200:'#fecdd3', 400:'#fb7185', 500:'#f43f5e', 600:'#e11d48', 700:'#be123c', 800:'#9f1239', 900:'#881337' },
  amber:    { 50:'#fffbeb', 100:'#fef3c7', 200:'#fde68a', 400:'#fbbf24', 500:'#f59e0b', 600:'#d97706', 700:'#b45309', 800:'#92400e', 900:'#78350f' },
  emerald:  { 50:'#ecfdf5', 100:'#d1fae5', 200:'#a7f3d0', 400:'#34d399', 500:'#10b981', 600:'#059669', 700:'#047857', 800:'#065f46', 900:'#064e3b' },
  sky:      { 50:'#f0f9ff', 100:'#e0f2fe', 200:'#bae6fd', 400:'#38bdf8', 500:'#0ea5e9', 600:'#0284c7', 700:'#0369a1', 800:'#075985', 900:'#0c4a6e' },
  teal:     { 50:'#f0fdfa', 100:'#ccfbf1', 200:'#99f6e4', 400:'#2dd4bf', 500:'#14b8a6', 600:'#0d9488', 700:'#0f766e', 800:'#115e59', 900:'#134e4a' },
  rose:     { 50:'#fff1f2', 100:'#ffe4e6', 200:'#fecdd3', 400:'#fb7185', 600:'#e11d48', 800:'#9f1239' },
};

export const globalStyles = `
  @import url('https://fonts.googleapis.com/css2?family=Sora:wght@300;400;500;600;700&family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;0,9..40,600;1,9..40,400&family=DM+Mono:wght@300;400;500&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --font-display: 'Sora', 'Plus Jakarta Sans', system-ui, sans-serif;
    --font-body:    'DM Sans', 'Manrope', system-ui, sans-serif;
    --font-mono:    'DM Mono', 'JetBrains Mono', monospace;
    --color-bg: #f3f7fc;
    --color-surface: #ffffff;
    --color-border: #dce6f2;
    --color-border-mid: #c7d5e6;
    --color-text-primary:   #0f172a;
    --color-text-secondary: #475569;
    --color-text-tertiary:  #94a3b8;
    --color-accent:      #1e5ed8;
    --color-accent-soft: #eaf2ff;
    --sidebar-w: 232px;
    --header-h:  56px;
    --r-sm: 6px; --r-md: 10px; --r-lg: 14px; --r-xl: 20px; --r-full: 9999px;
    --shadow-xs: 0 1px 2px rgba(15,23,42,0.05);
    --shadow-sm: 0 1px 3px rgba(15,23,42,0.08), 0 1px 2px rgba(15,23,42,0.04);
    --shadow-md: 0 4px 12px rgba(15,23,42,0.07), 0 2px 4px rgba(15,23,42,0.04);
    --shadow-lg: 0 10px 24px rgba(15,23,42,0.08), 0 4px 8px rgba(15,23,42,0.04);
  }
  html, body, #root { height: 100%; }
  body {
    font-family: var(--font-body); font-size: 14px; line-height: 1.6;
    color: var(--color-text-primary);
    background:
      radial-gradient(circle at 8% 10%, #e8f2ff 0%, transparent 32%),
      radial-gradient(circle at 92% 88%, #e5fbf5 0%, transparent 30%),
      var(--color-bg);
    -webkit-font-smoothing: antialiased;
  }
  ::-webkit-scrollbar { width: 4px; height: 4px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: #d1d9e6; border-radius: 99px; }
  ::-webkit-scrollbar-thumb:hover { background: #94a3b8; }
  input, select, textarea {
    font-family: var(--font-body); font-size: 13px;
    color: var(--color-text-primary); background: #fff;
    border: 1.5px solid var(--color-border); border-radius: var(--r-md);
    padding: 8px 12px; outline: none; width: 100%;
    transition: border-color 0.15s, box-shadow 0.15s;
  }
  input:focus, select:focus, textarea:focus {
    border-color: #6b98e9;
    box-shadow: 0 0 0 3px rgba(30,94,216,0.12);
  }
  textarea { resize: vertical; min-height: 80px; }
  @keyframes fadeUp { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:translateY(0); } }
  @keyframes spin { to { transform: rotate(360deg); } }
  @keyframes pulseDot { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.5;transform:scale(.8)} }
  @keyframes slideIn { from{opacity:0;transform:translateX(-8px)} to{opacity:1;transform:translateX(0)} }
  .page-enter { animation: fadeUp 0.22s ease both; }
`;

export const severityConfig = (sev) => {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return { bg:'#fff1f2', border:'#fecdd3', text:'#be123c', dot:'#f43f5e', label:'Critical' };
  if (s === 'high')     return { bg:'#fffbeb', border:'#fde68a', text:'#b45309', dot:'#f59e0b', label:'High'     };
  if (s === 'medium')   return { bg:'#edf6ff', border:'#cfe3ff', text:'#1e4f9b', dot:'#2d6bff', label:'Medium'   };
  if (s === 'low')      return { bg:'#ecfdf5', border:'#a7f3d0', text:'#047857', dot:'#10b981', label:'Low'      };
  return                        { bg:'#f1f5f9', border:'#e2e8f0', text:'#475569', dot:'#94a3b8', label: sev||'—'  };
};

export const statusConfig = (st) => {
  const s = (st || '').toLowerCase().replace(/_/g, '-');
  if (s === 'open')             return { bg:'#fff1f2', border:'#fecdd3', text:'#be123c' };
  if (s === 'investigating')    return { bg:'#fffbeb', border:'#fde68a', text:'#b45309' };
  if (s === 'contained')        return { bg:'#edf6ff', border:'#cfe3ff', text:'#1e4f9b' };
  if (s === 'resolved')         return { bg:'#ecfdf5', border:'#a7f3d0', text:'#047857' };
  if (s === 'closed')           return { bg:'#f1f5f9', border:'#e2e8f0', text:'#475569' };
  if (s === 'new')              return { bg:'#f0f9ff', border:'#bae6fd', text:'#0369a1' };
  if (s === 'infected')         return { bg:'#fff1f2', border:'#fecdd3', text:'#be123c' };
  if (s === 'suspicious')       return { bg:'#fffbeb', border:'#fde68a', text:'#b45309' };
  if (s === 'clean')            return { bg:'#ecfdf5', border:'#a7f3d0', text:'#047857' };
  if (s === 'running')          return { bg:'#f0f9ff', border:'#bae6fd', text:'#0369a1' };
  if (s === 'completed')        return { bg:'#ecfdf5', border:'#a7f3d0', text:'#047857' };
  if (s === 'active')           return { bg:'#ecfdf5', border:'#a7f3d0', text:'#047857' };
  if (s === 'false-positive')   return { bg:'#f1f5f9', border:'#e2e8f0', text:'#475569' };
  return                                { bg:'#f1f5f9', border:'#e2e8f0', text:'#475569' };
};
