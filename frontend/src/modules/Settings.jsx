import { useEffect, useMemo, useState } from "react";
import { Panel, Grid, Btn, Toggle, ProgressBar, Badge } from "../components/UI.jsx";

const STORAGE_KEY = "shieldgod.settings";

const defaults = {
  themeMode: "clinical-light",
  fontSize: 12,
  criticalThreshold: 85,
  anomalySensitivity: 42,
  retentionHotDays: 90,
  retentionColdYears: 7,
  retentionPcapHours: 24,
  channelEmail: true,
  channelSlack: true,
  channelSms: false,
};

function clamp(num, min, max) {
  return Math.max(min, Math.min(max, num));
}

export default function Settings({ appState, currentUser, onToast }) {
  const [settings, setSettings] = useState(defaults);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return;
      const parsed = JSON.parse(raw);
      setSettings((prev) => ({ ...prev, ...parsed }));
    } catch {
      // Ignore malformed local preferences and keep defaults.
    }
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
    } catch {
      // Ignore storage failures.
    }
  }, [settings]);

  const applyUiSettings = (nextSettings) => {
    const root = document.documentElement;
    const body = document.body;
    if (!root || !body) return;

    if (nextSettings.themeMode === "surgical-dark") {
      root.style.setProperty("--color-bg", "#0b1220");
      root.style.setProperty("--color-surface", "#111c31");
      root.style.setProperty("--color-border", "#263247");
      root.style.setProperty("--color-border-mid", "#33435d");
      root.style.setProperty("--color-text-primary", "#e2e8f0");
      root.style.setProperty("--color-text-secondary", "#cbd5e1");
      root.style.setProperty("--color-text-tertiary", "#8aa0c0");
      body.style.background = "radial-gradient(circle at 8% 10%, #12233f 0%, transparent 34%), radial-gradient(circle at 92% 88%, #12333b 0%, transparent 32%), #0b1220";
    } else {
      root.style.setProperty("--color-bg", "#f3f7fc");
      root.style.setProperty("--color-surface", "#ffffff");
      root.style.setProperty("--color-border", "#dce6f2");
      root.style.setProperty("--color-border-mid", "#c7d5e6");
      root.style.setProperty("--color-text-primary", "#0f172a");
      root.style.setProperty("--color-text-secondary", "#475569");
      root.style.setProperty("--color-text-tertiary", "#94a3b8");
      body.style.background = "radial-gradient(circle at 8% 10%, #e8f2ff 0%, transparent 32%), radial-gradient(circle at 92% 88%, #e5fbf5 0%, transparent 30%), #f3f7fc";
    }

    const scale = clamp(nextSettings.fontSize / 12, 0.86, 1.35);
    root.style.setProperty("--settings-font-scale", String(scale));
    body.style.fontSize = `${Math.round(14 * scale)}px`;
  };

  useEffect(() => {
    applyUiSettings(settings);
  }, [settings]);

  const activeSessionToken = useMemo(() => {
    const token = appState?.userSessionId || appState?.sessionId || "{data:text:text-4}";
    return String(token).slice(0, 22).toUpperCase();
  }, [appState]);

  const profile = {
    name: currentUser?.username || "Lead Analyst",
    role: "Lead Security Analyst",
    id: "SG-992-KUM",
    email: currentUser?.email || "r.kumar@shieldgod.internal",
    workstationIp: appState?.workstationIp || "10.0.4.128",
    clearance: "LEVEL_7",
    policy: "SENSITIVE_ISO",
    hardwareKey: "CONNECTED_YUBI_392",
  };

  const settingsCardStyle = {
    background: "#f8fafc",
    border: "1px solid #e2e8f0",
    borderRadius: "var(--r-md)",
    padding: "12px 14px",
  };

  const sectionLabel = {
    fontFamily: "var(--font-mono)",
    fontSize: 10,
    color: "#94a3b8",
    letterSpacing: "0.08em",
    textTransform: "uppercase",
    fontWeight: 600,
  };

  return (
    <div className="page-enter" style={{ display: "grid", gap: 16 }}>
      <div>
        <h2 style={{
          fontFamily: "var(--font-display)",
          fontSize: 30,
          lineHeight: 1.1,
          letterSpacing: "-0.02em",
          fontWeight: 700,
          color: "#0f172a",
          marginBottom: 6,
        }}>
          SYSTEM CONTROL
        </h2>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ width: 8, height: 8, borderRadius: 99, background: "#10b981", display: "inline-block" }} />
          <span style={{ ...sectionLabel, color: "#0f172a" }}>ACTIVE SESSION: {activeSessionToken}</span>
        </div>
      </div>

      <Grid cols={2} gap={16} style={{ gridTemplateColumns: "2fr 1.2fr" }}>
        <Panel title="ACCOUNT_PROFILE" padding="20px 22px">
          <div style={{ display: "grid", gap: 18 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "start", gap: 12 }}>
              <div>
                <div style={{ ...sectionLabel, marginBottom: 6 }}>Account</div>
                <div style={{ fontSize: 38, fontFamily: "var(--font-display)", letterSpacing: "-0.04em", fontWeight: 700, lineHeight: 1.05 }}>
                  {profile.name}
                </div>
                <div style={{ marginTop: 6, ...sectionLabel, color: "#334155" }}>
                  {profile.role} | ID: {profile.id}
                </div>
              </div>
              <Btn size="sm" variant="outline" onClick={() => onToast("Identity editor opens in next update", "info")}>
                EDIT_IDENTITY
              </Btn>
            </div>

            <div style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: 14,
            }}>
              <div style={settingsCardStyle}>
                <div style={sectionLabel}>PRIMARY_EMAIL</div>
                <div style={{ marginTop: 8, fontSize: 18, fontFamily: "var(--font-body)", color: "#0f172a", fontWeight: 600 }}>{profile.email}</div>
              </div>

              <div style={settingsCardStyle}>
                <div style={sectionLabel}>ACCESS_CLEARANCE</div>
                <div style={{ marginTop: 8, display: "flex", gap: 8, flexWrap: "wrap" }}>
                  <Badge label={profile.clearance} status="active" size="xs" />
                  <Badge label={profile.policy} status="new" size="xs" />
                </div>
              </div>

              <div style={settingsCardStyle}>
                <div style={sectionLabel}>WORKSTATION_IP</div>
                <div style={{ marginTop: 8, fontSize: 20, fontFamily: "var(--font-body)", color: "#0f172a", fontWeight: 700 }}>{profile.workstationIp}</div>
              </div>

              <div style={settingsCardStyle}>
                <div style={sectionLabel}>U2F_HARDWARE_KEY</div>
                <div style={{ marginTop: 8, fontFamily: "var(--font-body)", color: "#047857", fontSize: 16, fontWeight: 700 }}>
                  {profile.hardwareKey}
                </div>
              </div>
            </div>
          </div>
        </Panel>

        <Panel title="INTERFACE_PREFERENCES" padding="20px 22px">
          <div style={{ display: "grid", gap: 20 }}>
            <div>
              <div style={{ ...sectionLabel, marginBottom: 10 }}>VISUAL_ENGINE</div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                <button
                  type="button"
                  onClick={() => setSettings((p) => ({ ...p, themeMode: "clinical-light" }))}
                  style={{
                    border: settings.themeMode === "clinical-light" ? "1.5px solid #0ea5e9" : "1.5px solid #dbe3ee",
                    background: settings.themeMode === "clinical-light" ? "#f0f9ff" : "#ffffff",
                    color: "#0f172a",
                    borderRadius: "var(--r-md)",
                    padding: "14px 12px",
                    fontFamily: "var(--font-body)",
                    fontSize: 13,
                    fontWeight: 700,
                    cursor: "pointer",
                  }}
                >
                  CLINICAL_LIGHT
                </button>
                <button
                  type="button"
                  onClick={() => setSettings((p) => ({ ...p, themeMode: "surgical-dark" }))}
                  style={{
                    border: settings.themeMode === "surgical-dark" ? "1.5px solid #60a5fa" : "1.5px solid #dbe3ee",
                    background: "#0f172a",
                    color: "#bfdbfe",
                    borderRadius: "var(--r-md)",
                    padding: "14px 12px",
                    fontFamily: "var(--font-body)",
                    fontSize: 13,
                    fontWeight: 700,
                    cursor: "pointer",
                  }}
                >
                  SURGICAL_DARK
                </button>
              </div>
            </div>

            <div>
              <div style={{ ...sectionLabel, marginBottom: 10 }}>TYPOGRAPHY_DENSITY</div>
              <div style={{
                border: "1px solid #e2e8f0",
                background: "#f8fafc",
                borderRadius: "var(--r-md)",
                padding: "10px 12px",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 10,
              }}>
                <span style={{ fontFamily: "var(--font-body)", fontSize: 12, color: "#334155", fontWeight: 600 }}>APPLICATION_FONT_SCALE</span>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <Btn
                    size="xs"
                    variant="ghost"
                    onClick={() => setSettings((p) => ({ ...p, fontSize: clamp(p.fontSize - 1, 10, 16) }))}
                  >
                    -
                  </Btn>
                  <span style={{ fontFamily: "var(--font-body)", minWidth: 44, textAlign: "center", fontWeight: 700 }}>{settings.fontSize}PT</span>
                  <Btn
                    size="xs"
                    variant="ghost"
                    onClick={() => setSettings((p) => ({ ...p, fontSize: clamp(p.fontSize + 1, 10, 16) }))}
                  >
                    +
                  </Btn>
                </div>
              </div>
            </div>
          </div>
        </Panel>
      </Grid>

      <Panel title="CORE_SYSTEM_CONFIGURATION" padding="20px 22px">
        <div style={{
          display: "grid",
          gridTemplateColumns: "1.1fr 1fr 1fr",
          gap: 18,
        }}>
          <div>
            <div style={{ ...sectionLabel, color: "#0f172a", marginBottom: 14 }}>GLOBAL_ALERT_THRESHOLDS</div>
            <div style={{ marginBottom: 12 }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                <span style={{ ...sectionLabel, color: "#334155" }}>CRITICAL_EVENT_TRIGGER</span>
                <span style={{ ...sectionLabel, color: "#991b1b" }}>{settings.criticalThreshold}% SURGE</span>
              </div>
              <ProgressBar value={settings.criticalThreshold} max={100} color="#b91c1c" height={4} />
              <input
                type="range"
                min={40}
                max={99}
                step={1}
                value={settings.criticalThreshold}
                onChange={(e) => setSettings((p) => ({ ...p, criticalThreshold: Number(e.target.value) }))}
                style={{ marginTop: 8 }}
              />
            </div>
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                <span style={{ ...sectionLabel, color: "#334155" }}>ANOMALY_SENSITIVITY</span>
                <span style={{ ...sectionLabel, color: "#0e7490" }}>{settings.anomalySensitivity}MS DEVIATION</span>
              </div>
              <ProgressBar value={settings.anomalySensitivity} max={100} color="#0e7490" height={4} />
              <input
                type="range"
                min={5}
                max={95}
                step={1}
                value={settings.anomalySensitivity}
                onChange={(e) => setSettings((p) => ({ ...p, anomalySensitivity: Number(e.target.value) }))}
                style={{ marginTop: 8 }}
              />
            </div>
          </div>

          <div>
            <div style={{ ...sectionLabel, color: "#0f172a", marginBottom: 14 }}>DATA_RETENTION_POLICIES</div>
            <div style={{ display: "grid", gap: 10 }}>
              <div style={{ ...settingsCardStyle, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ ...sectionLabel, color: "#0f172a" }}>HOT STORAGE (SSD)</span>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <Btn size="xs" variant="ghost" onClick={() => setSettings((p) => ({ ...p, retentionHotDays: clamp(p.retentionHotDays - 1, 30, 365) }))}>-</Btn>
                  <span style={{ fontFamily: "var(--font-body)", fontWeight: 700, minWidth: 68, textAlign: "center" }}>{settings.retentionHotDays} DAYS</span>
                  <Btn size="xs" variant="ghost" onClick={() => setSettings((p) => ({ ...p, retentionHotDays: clamp(p.retentionHotDays + 1, 30, 365) }))}>+</Btn>
                </div>
              </div>
              <div style={{ ...settingsCardStyle, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ ...sectionLabel, color: "#0f172a" }}>COLD ARCHIVAL</span>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <Btn size="xs" variant="ghost" onClick={() => setSettings((p) => ({ ...p, retentionColdYears: clamp(p.retentionColdYears - 1, 1, 15) }))}>-</Btn>
                  <span style={{ fontFamily: "var(--font-body)", fontWeight: 700, minWidth: 68, textAlign: "center" }}>{settings.retentionColdYears} YEARS</span>
                  <Btn size="xs" variant="ghost" onClick={() => setSettings((p) => ({ ...p, retentionColdYears: clamp(p.retentionColdYears + 1, 1, 15) }))}>+</Btn>
                </div>
              </div>
              <div style={{ ...settingsCardStyle, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ ...sectionLabel, color: "#0f172a" }}>PCAP DUMPS</span>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <Btn size="xs" variant="ghost" onClick={() => setSettings((p) => ({ ...p, retentionPcapHours: clamp(p.retentionPcapHours - 1, 1, 96) }))}>-</Btn>
                  <span style={{ fontFamily: "var(--font-body)", fontWeight: 700, minWidth: 68, textAlign: "center" }}>{settings.retentionPcapHours} HOURS</span>
                  <Btn size="xs" variant="ghost" onClick={() => setSettings((p) => ({ ...p, retentionPcapHours: clamp(p.retentionPcapHours + 1, 1, 96) }))}>+</Btn>
                </div>
              </div>
            </div>
          </div>

          <div>
            <div style={{ ...sectionLabel, color: "#0f172a", marginBottom: 14 }}>NOTIFICATION_CHANNELS</div>
            <div style={{ display: "grid", gap: 10 }}>
              <div style={{ ...settingsCardStyle, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <span style={{ ...sectionLabel, color: "#0f172a" }}>EMAIL_SERVICE</span>
                <Toggle
                  value={settings.channelEmail}
                  onChange={(v) => setSettings((p) => ({ ...p, channelEmail: v }))}
                />
              </div>
              <div style={{ ...settingsCardStyle, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <span style={{ ...sectionLabel, color: "#0f172a" }}>SLACK_INTEGRATION</span>
                <Toggle
                  value={settings.channelSlack}
                  onChange={(v) => setSettings((p) => ({ ...p, channelSlack: v }))}
                />
              </div>
              <div style={{ ...settingsCardStyle, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <span style={{ ...sectionLabel, color: "#64748b" }}>SMS_GATEWAY</span>
                <Toggle
                  value={settings.channelSms}
                  onChange={(v) => setSettings((p) => ({ ...p, channelSms: v }))}
                />
              </div>
            </div>
          </div>
        </div>
      </Panel>

      <div style={{ display: "flex", justifyContent: "flex-end", gap: 10 }}>
        <Btn
          variant="ghost"
          onClick={() => {
            setSettings(defaults);
            applyUiSettings(defaults);
            onToast("Settings reset to defaults", "warning");
          }}
        >
          RESET
        </Btn>
        <Btn
          variant="primary"
          onClick={() => onToast("Settings saved locally", "success")}
        >
          APPLY_CONFIGURATION
        </Btn>
      </div>
    </div>
  );
}
