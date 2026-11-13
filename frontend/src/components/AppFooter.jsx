import { useEffect, useState } from "react";
import { API_BASE, getToken } from "../api/client.js";

export default function AppFooter() {
  const year = new Date().getFullYear();
  const [backendVersion, setBackendVersion] = useState("...");
  const frontendVersion = import.meta.env.VITE_APP_VERSION || "1.0.0";

  useEffect(() => {
    let mounted = true;

    const loadVersion = async () => {
      try {
        const token = getToken();
        const headers = token ? { Authorization: `Bearer ${token}` } : {};
        const res = await fetch(`${API_BASE}/dashboard/version`, { headers, signal: AbortSignal.timeout(5000) });
        if (!res.ok) {
          if (mounted) setBackendVersion("unavailable");
          return;
        }
        const body = await res.json();
        if (mounted) setBackendVersion(body.version || "unknown");
      } catch {
        if (mounted) setBackendVersion("unavailable");
      }
    };

    loadVersion();
    return () => { mounted = false; };
  }, []);

  return (
    <footer style={{
      borderTop: "1.5px solid #dbe5f5",
      background: "linear-gradient(90deg, #eff6ff 0%, #f8fafc 55%, #ecfeff 100%)",
      padding: "10px 16px",
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      gap: 10,
      fontSize: 11,
      color: "#334155",
      fontFamily: "var(--font-mono)",
    }}>
      <span>KavachOps AI SOC Platform · FE v{frontendVersion} · BE v{backendVersion}</span>
      <span>TM {year} KavachOps AI Security Systems. All rights reserved.</span>
      <span>Support: security@KavachOpsAI.local</span>
    </footer>
  );
}
