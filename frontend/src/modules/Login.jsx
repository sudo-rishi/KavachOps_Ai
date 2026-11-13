import { useState } from "react";
import { Btn, FormGroup } from "../components/UI.jsx";
import { API_BASE, ML_BASE } from "../api/client.js";

export const DEFAULT_LOGIN_CREDENTIALS = Object.freeze({
  username: "admin",
  password: "password",
});

export default function Login({ onLogin, error: externalError }) {
  const [username, setUsername] = useState(DEFAULT_LOGIN_CREDENTIALS.username);
  const [password, setPassword] = useState(DEFAULT_LOGIN_CREDENTIALS.password);
  const [localError, setLocalError] = useState("");
  const [loading,    setLoading]    = useState(false);

  const error = externalError || localError;

  const handle = async () => {
    setLocalError("");
    if (
      username !== DEFAULT_LOGIN_CREDENTIALS.username ||
      password !== DEFAULT_LOGIN_CREDENTIALS.password
    ) {
      setLocalError("Use the default frontend credentials shown below.");
      return;
    }

    setLoading(true);
    try {
      await onLogin({ username, role: "admin", frontendOnly: true });
    } catch (e) {
      setLocalError(e.message || "Login failed. Check your credentials.");
      setLoading(false);
    }
  };

  return (
    <div style={{
      height: "100dvh", minHeight: 0, overflow: "hidden",
      display: "flex", alignItems: "center", justifyContent: "center",
      background: "linear-gradient(140deg, #eaf2ff 0%, #f6f9fd 46%, #e9f8f3 100%)",
      padding: "clamp(8px, 2vh, 20px)",
    }}>
      {/* Background decoration */}
      <div style={{
        position: "fixed", inset: 0, pointerEvents: "none", overflow: "hidden",
      }}>
        <div style={{
          position: "absolute", top: -120, right: -120, width: 480, height: 480,
          borderRadius: "50%", background: "radial-gradient(circle, #d9e9ff66 0%, transparent 70%)",
        }} />
        <div style={{
          position: "absolute", bottom: -80, left: -80, width: 360, height: 360,
          borderRadius: "50%", background: "radial-gradient(circle, #ccfbf155 0%, transparent 70%)",
        }} />
      </div>

      {/* Cybersecurity network graphic */}
      <svg
        aria-hidden="true"
        viewBox="0 0 1200 800"
        preserveAspectRatio="none"
        style={{
          position: "fixed", inset: 0, width: "100%", height: "100%",
          pointerEvents: "none", opacity: 0.34, zIndex: 0,
        }}
      >
        <defs>
          <linearGradient id="cyberLine" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#2d6bff" stopOpacity="0.08" />
            <stop offset="100%" stopColor="#1a8797" stopOpacity="0.55" />
          </linearGradient>
          <pattern id="cyberGrid" width="48" height="48" patternUnits="userSpaceOnUse">
            <path d="M 48 0 L 0 0 0 48" fill="none" stroke="#2d6bff" strokeOpacity="0.06" strokeWidth="1" />
          </pattern>
        </defs>
        <rect width="1200" height="800" fill="url(#cyberGrid)" />
        <g fill="none" stroke="url(#cyberLine)" strokeWidth="2">
          <path d="M0 170 H170 V110 H290" />
          <path d="M0 610 H210 V680 H330" />
          <path d="M1200 190 H1030 V250 H920" />
          <path d="M1200 650 H1010 V580 H890" />
          <path d="M90 330 H230 V390 H330" strokeDasharray="5 8" />
          <path d="M1110 370 H970 V430 H870" strokeDasharray="5 8" />
        </g>
        <g fill="#2d6bff">
          <circle cx="170" cy="170" r="5" />
          <circle cx="210" cy="610" r="5" />
          <circle cx="1030" cy="190" r="5" />
          <circle cx="1010" cy="650" r="5" />
        </g>
        <g transform="translate(92 228)" fill="none" stroke="#2d6bff" strokeOpacity="0.12" strokeWidth="3">
          <path d="M70 0 L128 22 V76 C128 120 102 151 70 166 C38 151 12 120 12 76 V22 Z" />
          <path d="M46 78 H94 M70 54 V104" stroke="#1a8797" />
        </g>
        <g transform="translate(1030 500)" fill="none" stroke="#1a8797" strokeOpacity="0.15" strokeWidth="3">
          <circle cx="55" cy="55" r="48" />
          <path d="M55 18 V92 M18 55 H92" />
          <circle cx="55" cy="55" r="8" fill="#1a8797" stroke="none" />
        </g>
      </svg>

      <div style={{
        width: "min(500px, calc(100vw - 32px))", background: "#ffffff", borderRadius: 18,
        boxShadow: "0 20px 50px rgba(15,23,42,0.12), 0 4px 14px rgba(15,23,42,0.05)",
        border: "1px solid #dfe6ef", overflow: "hidden", position: "relative", zIndex: 1,
        animation: "fadeUp 0.3s ease",
      }}>
        {/* Header */}
        <div style={{
          padding: "clamp(22px, 4vh, 40px) 48px clamp(18px, 3vh, 30px)",
          background: "linear-gradient(135deg, #f0f5ff 0%, #f8fafc 100%)",
          borderBottom: "1.5px solid #e8ecf2", textAlign: "center",
        }}>
          <div style={{
            width: "clamp(52px, 8vh, 64px)", height: "clamp(52px, 8vh, 64px)",
            borderRadius: 16, margin: "0 auto clamp(10px, 2vh, 16px)",
            background: "#ffffff", overflow: "hidden",
            display: "flex", alignItems: "center", justifyContent: "center",
            boxShadow: "0 10px 26px rgba(31,95,217,0.28)", fontSize: 22,
            color: "#ffffff", fontWeight: 800, fontFamily: "var(--font-display)",
          }}>
            <img
              src="/kavachops-logo.png"
              alt="KavachOps AI logo"
              style={{
                width: "100%", height: "100%", objectFit: "contain",
                transform: "none",
              }}
            />
          </div>
          <h1 style={{
            fontFamily: "var(--font-display)", fontSize: 24, fontWeight: 800,
            background: "linear-gradient(135deg, #0f2b5f 0%, #0f766e 100%)",
            WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
            letterSpacing: "-0.04em", marginBottom: 6,
          }}>KavachOps AI</h1>
          <p style={{
            fontSize: 13, fontWeight: 800, letterSpacing: "0.04em",
            background: "linear-gradient(90deg, #0284c7 0%, #0f9f9a 100%)",
            WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
          }}>
      Sarvam Sarva Raksha
          </p>
          <div style={{ marginTop: 10, fontSize: 11, color: "#475569", lineHeight: 1.45 }}>
            Smart cybersecurity powered by AI-driven threat detection and real-time protection.<br />
            Monitor, analyze, and secure your digital environment.
          </div>
        </div>

        {/* Form */}
        <div style={{ padding: "clamp(18px, 3vh, 32px) 48px clamp(20px, 3vh, 36px)" }}>
          {error && (
            <div style={{
              background: "#fff1f2", border: "1.5px solid #fecdd3", color: "#be123c",
              borderRadius: "var(--r-md)", padding: "10px 14px", fontSize: 13,
              marginBottom: 18, display: "flex", alignItems: "center", gap: 8,
            }}>
              <span>⚠</span> {error}
            </div>
          )}

          <FormGroup label="Operator ID">
            <input
              value={username} onChange={e => setUsername(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handle()}
              placeholder="admin" autoFocus
            />
          </FormGroup>

          <FormGroup label="Access Code">
            <input
              type="password" value={password}
              onChange={e => setPassword(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handle()}
              placeholder="••••••••••"
            />
          </FormGroup>

          <Btn
            variant="primary" onClick={handle} disabled={loading}
            style={{ width: "100%", justifyContent: "center", padding: "11px 0",
              fontSize: 14, marginTop: 8, borderRadius: "var(--r-md)",
              opacity: loading ? 0.7 : 1,
            }}
          >
            {loading ? "Authenticating…" : "Authenticate & Access ›"}
          </Btn>

          <div style={{
            marginTop: 20, padding: "12px 14px", background: "#f8fafc",
            borderRadius: "var(--r-md)", border: "1.5px solid #e8ecf2",
          }}>
            <div style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "#64748b", marginBottom: 4 }}>
              DEFAULT CREDENTIALS
            </div>
            <div style={{ fontSize: 12, color: "#475569" }}>
                <strong>admin</strong> / password
            </div>
            <div style={{ fontSize: 10, color: "#64748b", marginTop: 8, lineHeight: 1.5 }}>
              Frontend: http://localhost:5173<br />
              Backend API: {API_BASE}<br />
              ML Service: {ML_BASE}
            </div>
          </div>

          <div style={{
            marginTop: 14,
            fontSize: 10,
            color: "#64748b",
            textAlign: "center",
            fontFamily: "var(--font-mono)",
            borderTop: "1px solid #e2e8f0",
            paddingTop: 10,
          }}>
            TM {new Date().getFullYear()} KavachOps AI Security Systems · security@KavachOpsAI.local
          </div>
        </div>
      </div>
    </div>
  );
}
