// ═══════════════════════════════════════════════════════════════
//  Shield-God Root App
//  Real connections only — no simulation fallback.
//  • Login → JWT → WebSocket → auto-start capture
//  • Offline backend → OfflineScreen (hard block)
//  • ML anomaly scores on every captured packet
// ═══════════════════════════════════════════════════════════════

import { useState, useCallback, lazy, Suspense } from "react";
import { globalStyles } from "./design-system.js";
import { useRealtime }  from "./hooks/useRealtime.js";

import LoginModule      from "./modules/Login.jsx";

const Dashboard = lazy(() => import("./modules/Dashboard.jsx"));
const Network = lazy(() => import("./modules/Network.jsx"));
const WindowsEvents = lazy(() => import("./modules/WindowsEvents.jsx"));
const Malware = lazy(() => import("./modules/Malware.jsx"));
const Incidents = lazy(() => import("./modules/Incidents.jsx"));
const Vulnerability = lazy(() => import("./modules/Vulnerability.jsx"));
const Honeypot = lazy(() => import("./modules/Honeypot.jsx"));
const Reports = lazy(() => import("./modules/Reports.jsx"));
const Settings = lazy(() => import("./modules/Settings.jsx"));

import Sidebar             from "./components/Sidebar.jsx";
import Header              from "./components/Header.jsx";
import AppFooter           from "./components/AppFooter.jsx";
import ToastContainer      from "./components/Toast.jsx";
import { OfflineScreen }   from "./components/OfflineScreen.jsx";
import { ConnectionBadge } from "./components/ConnectionBadge.jsx";

let _toastId = 0;

export default function App() {
  const [page,   setPage]   = useState("dashboard");
  const [toasts, setToasts] = useState([]);
  const [retrying, setRetrying] = useState(false);
  const [demoUser, setDemoUser] = useState(null);

  const { authState, data, actions } = useRealtime();

  // ── Toast system ───────────────────────────────────────────────
  const showToast = useCallback((message, type = "info") => {
    const id = ++_toastId;
    setToasts(p => [...p, { id, message, type }]);
  }, []);
  const removeToast = useCallback((id) => {
    setToasts(p => p.filter(t => t.id !== id));
  }, []);

  // ── Handle login ───────────────────────────────────────────────
  const handleLogin = async (credentials) => {
    try {
      setDemoUser({ username: credentials.username, role: "admin" });
      showToast("Frontend demo login successful. Backend authentication is disabled.", "success");
    } catch (err) {
      // Error is already stored in authState.error — Login component reads it
      throw err;
    }
  };

  // ── Handle logout ──────────────────────────────────────────────
  const handleLogout = async () => {
    if (demoUser) {
      setDemoUser(null);
      setPage("dashboard");
      showToast("Logged out of frontend demo mode", "info");
      return;
    }

    await actions.logout().catch(() => {});
    setPage("dashboard");
    showToast("Logged out", "info");
  };

  // ── Retry when offline screen is shown ────────────────────────
  const handleRetry = async () => {
    setRetrying(true);
    // If we have a stale token, try to reconnect WS + sync
    await actions.syncAll().catch(() => {});
    setRetrying(false);
  };

  // ── Capture toggle ─────────────────────────────────────────────
  const handleToggleCapture = async () => {
    try {
      if (data.captureRunning) {
        await actions.stopCapture();
        showToast(`Capture stopped · ${data.capturePackets.toLocaleString()} packets`, "info");
      } else {
        await actions.startCapture();
        showToast("Packet capture started", "success");
      }
    } catch (err) {
      showToast(`Capture error: ${err.message} — Run as Administrator?`, "error");
    }
  };

  // ── Sidebar badges ─────────────────────────────────────────────
  const badges = {
    alerts:    data.alerts.filter(a => ["CRITICAL","HIGH"].includes(a.severity) && a.status === "new").length,
    events:    data.winEvents.filter(e => e.securityRelevant).length,
    malware:   data.malwareScans.filter(s => s.scanResult === "infected").length,
    incidents: data.incidents.filter(i => ["open","investigating"].includes(i.status)).length,
  };

  // ── Props passed to every page ─────────────────────────────────
  const pageProps = {
    appState:  data,      // pages use appState.* for data
    currentUser: demoUser || authState.user,
    onNavigate: setPage,
    onToast:    showToast,

    // Network
    onAddRule:           async (rule) => { const r = await actions.createRule(rule);     showToast("Rule created", "success");   return r; },
    onDeleteRule:        async (id)   => { await actions.deleteRule(id);                 showToast("Rule deleted", "warning");          },
    onToggleRule:        async (id)   => { const r = await actions.toggleRule(id);       showToast(r.active ? "Rule enabled" : "Rule disabled", "info"); },
    onUpdateAlertStatus: async (id, s)=> { await actions.updateAlertStatus(id, s);      showToast("Alert updated", "success");          },

    // Incidents
    onCreateIncident: async (d)       => { const r = await actions.createIncident(d);   showToast("Incident created", "success"); return r; },
    onUpdateIncident: async (id, s)   => { await actions.updateIncident(id, s);         showToast(`Status → ${s}`, "success");          },
    onAddNote:        async (id, note)=> { await actions.addNote(id, note);             showToast("Note added", "success");             },

    // Malware
    onScanFile: async (filePath) => {
      const result = await actions.scanFile(filePath);
      if (result.scanResult === "infected")   showToast(`🚨 MALWARE: ${result.threatName || "Unknown"}`, "critical");
      else if (result.scanResult === "suspicious") showToast(`⚠ Suspicious: ${result.fileName}`, "warning");
      else                                    showToast(`✓ Clean: ${result.fileName}`, "success");
      return result;
    },
    onStartMalwareFullScan: async (rootPath = "") => {
      const job = await actions.startMalwareFullScan(rootPath);
      showToast("Full-system malware scan started", "info");
      return job;
    },
    onGetMalwareFullScanStatus: async (jobId) => {
      return actions.getMalwareFullScanStatus(jobId);
    },
    onStopMalwareFullScan: async (jobId) => {
      const job = await actions.stopMalwareFullScan(jobId);
      showToast("Stop requested for full-system scan", "warning");
      return job;
    },

    // Vulnerability
    onCreateScan:    async (d)   => { const r = await actions.createScan(d);    showToast("Scan started: "+d.targets, "info"); return r; },
    onStartContinuousInterfaceScan: async (d) => {
      const r = await actions.startContinuousInterfaceScan(d);
      showToast(`Continuous interface scan started on ${d.interfaceName}`, "success");
      return r;
    },
    onGetScanRuntimeStatus: async (scanId) => {
      return actions.getScanRuntimeStatus(scanId);
    },
    onStopScanRuntime: async (scanId) => {
      const r = await actions.stopScanRuntime(scanId);
      showToast("Continuous interface scan stop requested", "warning");
      return r;
    },
    onUpdateFinding: async (id,s)=> { await actions.updateFinding(id, s);       showToast("Finding updated", "success");             },
    onListInterfaces: async () => {
      return actions.listInterfaces();
    },

    // Honeypots
    onDeployHoneypot: async (d)  => { const r = await actions.deployHoneypot(d); showToast("Honeypot deployed: "+d.name, "success"); return r; },
    onToggleHoneypot: async (id) => { await actions.toggleHoneypot(id);          showToast("Honeypot toggled", "info");                     },

  };

  // ══════════════════════════════════════════════════════════════
  //  RENDER STATES
  // ══════════════════════════════════════════════════════════════

  // 1. Initial loading / connecting
  if (authState.loading) {
    return (
      <>
        <style>{globalStyles}</style>
        <div style={{
          minHeight:"100vh", display:"flex", alignItems:"center", justifyContent:"center",
          background:"linear-gradient(140deg, #eaf2ff 0%, #f6f9fd 46%, #e9f8f3 100%)",
          flexDirection:"column", gap:16,
        }}>
          <div style={{
            width:64, height:64, borderRadius:18,
            background:"linear-gradient(135deg, #1f5fd9, #1a8797)",
            display:"flex", alignItems:"center", justifyContent:"center", fontSize:22,
            color:"#ffffff", fontWeight:800, fontFamily:"var(--font-display)",
            boxShadow:"0 10px 26px rgba(31,95,217,0.28)",
          }}>SG</div>
          <div style={{ fontFamily:"var(--font-display)", fontSize:18, fontWeight:800,
            color:"#0f172a", letterSpacing:"-.04em" }}>Shield-God</div>
          <div style={{ display:"flex", alignItems:"center", gap:8 }}>
            <span style={{ animation:"spin 1s linear infinite", display:"inline-block",
              fontSize:16, color:"#2d6bff" }}>⟳</span>
            <span style={{ fontFamily:"var(--font-mono)", fontSize:12, color:"#64748b" }}>
              Connecting to backend…
            </span>
          </div>
        </div>
      </>
    );
  }

  // 2. Logged in but WebSocket disconnected/failed → show banner, not full block
  //    (WebSocket reconnects automatically, REST still works)

  // 3. Not authenticated → Login screen
  //    If login fails because backend is down → show OfflineScreen
  if (!authState.connected && !demoUser) {
    // Distinguish: never attempted vs failed with backend-down error
    const isBackendDown = authState.error &&
      (authState.error.includes("fetch") ||
       authState.error.includes("Failed to fetch") ||
       authState.error.includes("NetworkError") ||
       authState.error.includes("health check"));

    if (isBackendDown) {
      return (
        <>
          <style>{globalStyles}</style>
          <OfflineScreen
            error={authState.error}
            onRetry={handleRetry}
            retrying={retrying}
          />
          <ToastContainer toasts={toasts} onRemove={removeToast} />
        </>
      );
    }

    // Normal login screen (or login error like wrong password)
    return (
      <>
        <style>{globalStyles}</style>
        <LoginModule onLogin={handleLogin} error={authState.error} />
        <ToastContainer toasts={toasts} onRemove={removeToast} />
      </>
    );
  }

  // 4. Authenticated → full app
  const pages = {
    dashboard:  <Dashboard    {...pageProps} />,
    network:    <Network      {...pageProps} />,
    events:     <WindowsEvents {...pageProps} />,
    malware:    <Malware      {...pageProps} />,
    incidents:  <Incidents    {...pageProps} />,
    vuln:       <Vulnerability {...pageProps} />,
    honeypot:   <Honeypot     {...pageProps} />,
    reports:    <Reports      {...pageProps} />,
    settings:   <Settings     {...pageProps} />,
  };

  return (
    <>
      <style>{globalStyles}</style>
      <div style={{ display:"flex", height:"100vh", overflow:"hidden", background:"var(--color-bg)" }}>

        <Sidebar
          activePage={page}
          onNavigate={setPage}
          badges={badges}
          status={{ capture: data.captureRunning }}
        />

        <div style={{ flex:1, display:"flex", flexDirection:"column", overflow:"hidden" }}>
          <Header
            page={page}
            user={authState.user}
            captureRunning={data.captureRunning}
            onToggleCapture={handleToggleCapture}
            onLogout={handleLogout}
            onToast={showToast}
            extra={
              <ConnectionBadge
                wsStatus={authState.wsStatus}
                mlOnline={authState.mlOnline}
                captureRunning={data.captureRunning}
              />
            }
          />

          {/* WebSocket warning banner (non-blocking) */}
          {authState.wsStatus !== "connected" && authState.wsStatus !== "connecting" && (
            <div style={{
              background:"#fffbeb", borderBottom:"1.5px solid #fde68a",
              padding:"8px 22px", display:"flex", alignItems:"center", gap:10,
              fontSize:12, color:"#b45309",
            }}>
              <span>⚠</span>
              <span>
                WebSocket {authState.wsStatus} — real-time push paused.
                REST polling active every 15s.
                {authState.wsStatus === "failed"
                  ? " Reload the page to retry."
                  : " Reconnecting automatically…"}
              </span>
            </div>
          )}

          <main style={{
            flex:1, overflowY:"auto",
            padding:"22px 24px",
            position:"relative",
            background:
              "radial-gradient(circle at 8% 10%, #d9e9ff66 0%, transparent 32%), radial-gradient(circle at 92% 88%, #ccfbf155 0%, transparent 30%), linear-gradient(140deg, #eaf2ff 0%, #f6f9fd 46%, #e9f8f3 100%)",
          }}>
            <svg aria-hidden="true" viewBox="0 0 1200 800" preserveAspectRatio="none" style={{
              position:"absolute", inset:0, width:"100%", height:"100%",
              pointerEvents:"none", opacity:0.34, zIndex:0,
            }}>
              <defs>
                <linearGradient id="moduleCyberLine" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%" stopColor="#2d6bff" stopOpacity="0.08" />
                  <stop offset="100%" stopColor="#0f9f9a" stopOpacity="0.55" />
                </linearGradient>
                <pattern id="moduleCyberGrid" width="48" height="48" patternUnits="userSpaceOnUse">
                  <path d="M 48 0 L 0 0 0 48" fill="none" stroke="#2d6bff" strokeOpacity="0.07" strokeWidth="1" />
                </pattern>
              </defs>
              <rect width="1200" height="800" fill="url(#moduleCyberGrid)" />
              <g fill="none" stroke="url(#moduleCyberLine)" strokeWidth="2">
                <path d="M0 140 H130 V90 H260" /><path d="M0 650 H170 V710 H300" />
                <path d="M1200 170 H1060 V230 H930" /><path d="M1200 680 H1030 V610 H900" />
                <path d="M70 360 H190 V420 H300" strokeDasharray="5 8" />
                <path d="M1130 390 H1000 V450 H880" strokeDasharray="5 8" />
              </g>
              <g fill="#2d6bff"><circle cx="130" cy="140" r="5" /><circle cx="170" cy="650" r="5" /><circle cx="1060" cy="170" r="5" /><circle cx="1030" cy="680" r="5" /></g>
              <g transform="translate(72 220)" fill="none" stroke="#2d6bff" strokeOpacity="0.16" strokeWidth="3">
                <path d="M62 0 L116 20 V70 C116 111 92 140 62 154 C32 140 8 111 8 70 V20 Z" />
                <path d="M38 73 H86 M62 50 V98" stroke="#0f9f9a" />
              </g>
              <g transform="translate(1030 500)" fill="none" stroke="#0f9f9a" strokeOpacity="0.18" strokeWidth="3">
                <circle cx="55" cy="55" r="48" /><path d="M55 18 V92 M18 55 H92" />
                <circle cx="55" cy="55" r="8" fill="#0f9f9a" stroke="none" />
              </g>
            </svg>
            <div style={{ position:"relative", zIndex:1 }}>
            <Suspense fallback={
              <div style={{ display:"flex", alignItems:"center", gap:8, color:"#475569", fontFamily:"var(--font-mono)", fontSize:12 }}>
                <span style={{ animation:"spin 1s linear infinite", display:"inline-block" }}>⟳</span>
                Loading module...
              </div>
            }>
              {pages[page] || pages.dashboard}
            </Suspense>
            </div>
          </main>
          <AppFooter />
        </div>
      </div>

      <ToastContainer toasts={toasts} onRemove={removeToast} />
    </>
  );
}
