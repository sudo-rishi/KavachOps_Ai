// ═══════════════════════════════════════════════════════════════
//  useRealtime — Manages all live data from Shield-God backend
//  • Polls REST every SYNC_MS for bulk data
//  • Receives WebSocket pushes for real-time updates
//  • Auto-starts packet capture after login
//  • Enriches alerts with ML anomaly scores
//  • No simulation fallback — errors surface to the UI
// ═══════════════════════════════════════════════════════════════

import { useState, useEffect, useRef, useCallback } from "react";
import {
  setToken, clearToken, getToken,
  auth as authApi,
  network  as networkApi,
  events   as eventsApi,
  malware  as malwareApi,
  incidents as incApi,
  vulnerability as vulnApi,
  honeypots as hpApi,
  dashboard as dashApi,
  ml        as mlApi,
} from "../api/client.js";
import { ws, TOPICS } from "../services/websocket.js";
import { fmtTime } from "../utils/dateFormatter.js";

const SYNC_MS   = 15_000;   // REST sync interval
const HEALTH_MS = 10_000;   // health check interval
const FEED_MAX = 60;
const TRAFFIC_FEED_INTERVAL = 25;

const MLTEST_FEATURE_COLUMNS = [
  "state", "usage_counter", "prio", "static_prio", "normal_prio",
  "policy", "vm_pgoff", "vm_truncate_count", "task_size",
  "cached_hole_size", "free_area_cache", "mm_users", "map_count",
  "hiwater_rss", "total_vm", "shared_vm", "exec_vm", "reserved_vm",
  "nr_ptes", "end_data", "last_interval", "nvcsw", "nivcsw",
  "min_flt", "maj_flt", "fs_excl_counter", "lock", "utime",
  "stime", "gtime", "cgtime", "signal_nvcsw",
];

function toFiniteNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function hashChunk(hash = "", start = 0, len = 8) {
  const chunk = String(hash).slice(start, start + len).padEnd(len, "0");
  const parsed = parseInt(chunk, 16);
  return Number.isFinite(parsed) ? parsed : 0;
}

function buildMlTestFeatures(scan = {}) {
  const fileSize = Math.max(0, toFiniteNumber(scan.fileSize, 0));
  const hash = String(scan.fileHash || "").toLowerCase();

  const derived = {
    state: 0,
    usage_counter: hashChunk(hash, 0, 8),
    prio: fileSize % 65536,
    static_prio: 0,
    normal_prio: 0,
    policy: 0,
    vm_pgoff: hashChunk(hash, 8, 8),
    vm_truncate_count: 0,
    task_size: fileSize,
    cached_hole_size: fileSize % 1024,
    free_area_cache: hashChunk(hash, 16, 6) % 1000000,
    mm_users: (hashChunk(hash, 22, 4) % 10000) + 1,
    map_count: Math.max(1, Math.floor(fileSize / 4096)),
    hiwater_rss: Math.max(1, Math.floor(fileSize / 1024)),
    total_vm: Math.max(1, Math.floor(fileSize / 512)),
    shared_vm: Math.max(0, Math.floor(fileSize / 2048)),
    exec_vm: Math.max(0, Math.floor(fileSize / 8192)),
    reserved_vm: 0,
    nr_ptes: Math.max(1, Math.floor(fileSize / 16384)),
    end_data: hashChunk(hash, 26, 6) % 1000000,
    last_interval: hashChunk(hash, 32, 8),
    nvcsw: hashChunk(hash, 40, 4) % 100000,
    nivcsw: hashChunk(hash, 44, 4) % 100000,
    min_flt: Math.max(0, Math.floor(fileSize / 8192)),
    maj_flt: Math.max(0, Math.floor(fileSize / (1024 * 1024))),
    fs_excl_counter: hashChunk(hash, 48, 8),
    lock: hashChunk(hash, 56, 6) % 1000000,
    utime: Math.max(0, Math.floor(fileSize / 4096)),
    stime: Math.max(0, Math.floor(fileSize / 32768)),
    gtime: 0,
    cgtime: 0,
    signal_nvcsw: hashChunk(hash, 60, 4) % 100000,
  };

  // Allow backend-provided telemetry to override derived defaults when available.
  const overrides = (scan.mlFeatures && typeof scan.mlFeatures === "object") ? scan.mlFeatures : {};
  const merged = { ...derived, ...overrides };

  const features = {};
  for (const key of MLTEST_FEATURE_COLUMNS) {
    features[key] = toFiniteNumber(merged[key], 0);
  }
  return features;
}

function normalizeFeedSeverity(input) {
  const raw = String(input || "").toUpperCase();
  if (["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(raw)) return raw;
  if (["ERROR", "WARN", "WARNING"].includes(raw)) return "HIGH";
  if (["INFO", "INFORMATION", "DEBUG", "TRACE"].includes(raw)) return "LOW";
  return "MEDIUM";
}

// ─────────────────────────────────────────────────────────────────
export function useRealtime() {
  // ── Auth & connectivity ─────────────────────────────────────────
  const [authState, setAuthState] = useState({
    loading:   true,    // initial connection check
    connected: false,   // backend reachable + JWT obtained
    wsStatus:  "disconnected",
    mlOnline:  false,
    error:     null,    // human-readable error to show on login/offline screen
    user:      null,
  });

  // ── Live data ───────────────────────────────────────────────────
  const [data, setData] = useState({
    alerts:       [],
    incidents:    [],
    malwareScans: [],
    winEvents:    [],
    idsRules:     [],
    vulnFindings: [],
    vulnScans:    [],
    honeypots:    [],
    attackers:    [],
    users:        [],
    capturePackets: 0,
    captureRunning: false,
    captureLoops:   0,
    captureRestarts: 0,
    trafficFeed:    [],
    feedItems:      [],
    dashStats:      null,
    honeypotStats:  null,
    mlStatus:       null,
  });

  const syncTimerRef   = useRef(null);
  const healthTimerRef = useRef(null);
  const pktCountRef    = useRef(0);

  // ── Helpers ─────────────────────────────────────────────────────
  const patch = useCallback((updates) => {
    setData(p => ({ ...p, ...updates }));
  }, []);

  const patchAuth = useCallback((updates) => {
    setAuthState(p => ({ ...p, ...updates }));
  }, []);

  // Restore previous login if token exists, otherwise show login immediately.
  useEffect(() => {
    const restore = async () => {
      const existingToken = getToken();
      if (!existingToken) {
        patchAuth({ loading: false, connected: false, error: null, user: null });
        return;
      }

      try {
        const me = await authApi.me();
        ws.connect(existingToken);

        const mlStatus = await mlApi.health().catch(() => null);

        patchAuth({
          loading: false,
          connected: true,
          mlOnline: !!mlStatus,
          error: null,
          user: me,
        });

        setData(p => ({ ...p, mlStatus }));
      } catch {
        clearToken();
        patchAuth({ loading: false, connected: false, error: null, user: null });
      }
    };

    restore();
  }, [patchAuth]);

  // ── ML enrichment: run anomaly detection on a traffic record ────
  const enrichWithMl = useCallback(async (trafficRecord) => {
    try {
      const result = await mlApi.detectAnomaly(trafficRecord);
      return result;
    } catch {
      return null; // ML call failed silently — don't break traffic flow
    }
  }, []);

  // ── WebSocket subscriptions ─────────────────────────────────────
  useEffect(() => {
    const unsubs = [
      // Real-time alerts pushed by AlertBroadcaster.java
      ws.on(TOPICS.ALERTS, (alert) => {
        const alertTime = fmtTime(alert.timestamp || Date.now());
        const normalizedSeverity = normalizeFeedSeverity(alert.severity || alert.level);
        const hasPersistentAlertId = alert.alertId !== undefined && alert.alertId !== null;
        const liveFeedItem = {
          time: alertTime,
          severity: normalizedSeverity,
          label: alert.alertType || "ALERT",
          message: alert.message || alert.alertMessage || "Alert event",
        };

        setData(p => ({
          ...p,
          alerts: !hasPersistentAlertId
            ? p.alerts
            : p.alerts.some(a => a.alertId === alert.alertId)
              ? p.alerts.map(a => a.alertId === alert.alertId ? { ...a, ...alert, severity: normalizedSeverity } : a)
              : [{ ...alert, severity: normalizedSeverity }, ...p.alerts],
          feedItems: [liveFeedItem, ...p.feedItems].slice(0, FEED_MAX),
        }));
      }),

      // Live packet metadata from PacketCaptureEngine.java
      ws.on(TOPICS.TRAFFIC, async (pkt) => {
        pktCountRef.current += 1;

        // Optional ML enrichment
        let anomalyScore = null;
        if (authState.mlOnline) {
          const ml = await enrichWithMl({
            sourceIp:      pkt.sourceIp,
            destinationIp: pkt.destinationIp,
            protocol:      pkt.protocol,
            sourcePort:    pkt.sourcePort,
            destinationPort: pkt.destPort,
            packetSize:    pkt.packetSize,
            timestamp:     pkt.timestamp,
          });
          anomalyScore = ml?.anomalyScore ?? null;
        }

        setData(p => ({
          ...p,
          capturePackets: pktCountRef.current,
          captureRunning: true,
          trafficFeed: [{
            time:         fmtTime(pkt.timestamp || Date.now()),
            src:          pkt.sourceIp,
            dst:          pkt.destinationIp,
            protocol:     pkt.protocol,
            port:         pkt.destPort,
            size:         pkt.packetSize,
            anomalyScore,
          }, ...p.trafficFeed].slice(0, 100),
          feedItems: pktCountRef.current % TRAFFIC_FEED_INTERVAL !== 0
            ? p.feedItems
            : [{
                time: fmtTime(pkt.timestamp || Date.now()),
                severity: "LOW",
                label: "TRAFFIC",
                message: `${pkt.protocol || "IP"} ${pkt.sourceIp || "?"} -> ${pkt.destinationIp || "?"}${pkt.destPort ? `:${pkt.destPort}` : ""}`,
              }, ...p.feedItems].slice(0, FEED_MAX),
        }));
      }),

      // Windows Event Log entries from WindowsEventLogReader.java
      ws.on(TOPICS.EVENTS, (event) => {
        setData(p => ({
          ...p,
          winEvents: p.winEvents.some(e => e.logId === event.logId)
            ? p.winEvents
            : [event, ...p.winEvents].slice(0, 200),
          feedItems: !event.securityRelevant
            ? p.feedItems
            : [{
                time: fmtTime(event.eventTime || Date.now()),
                severity: normalizeFeedSeverity(event.level),
                label: "WIN_EVENT",
                message: `Event ${event.eventId || "?"} on ${event.channel || "unknown"}`,
              }, ...p.feedItems].slice(0, FEED_MAX),
        }));
      }),

      // Incident create / update from IncidentService.java
      ws.on(TOPICS.INCIDENTS, (incident) => {
        setData(p => ({
          ...p,
          incidents: p.incidents.some(i => i.incidentId === incident.incidentId)
            ? p.incidents.map(i => i.incidentId === incident.incidentId ? { ...i, ...incident } : i)
            : [incident, ...p.incidents],
          feedItems: [{
            time: fmtTime(incident.createdAt || Date.now()),
            severity: normalizeFeedSeverity(incident.severity),
            label: "INCIDENT",
            message: `${incident.incidentNumber || "INC"} ${incident.title || "updated"}`,
          }, ...p.feedItems].slice(0, FEED_MAX),
        }));
      }),

      // Aggregated dashboard stats (every 10s from DashboardController.java)
      ws.on(TOPICS.DASHBOARD, (stats) => {
        setData(p => ({
          ...p,
          dashStats:      stats,
          capturePackets: stats.capture?.packets ?? p.capturePackets,
          captureRunning: stats.capture?.running  ?? p.captureRunning,
          captureLoops: stats.capture?.loops ?? p.captureLoops,
          captureRestarts: stats.capture?.restarts ?? p.captureRestarts,
        }));
      }),

      // WebSocket connection status
      ws.onStatus((status) => patchAuth({ wsStatus: status })),
    ];

    return () => unsubs.forEach(u => u());
  }, [authState.mlOnline, enrichWithMl, patchAuth]);

  // ── Full REST sync ───────────────────────────────────────────────
  const syncAll = useCallback(async () => {
    if (!authState.connected) return;
    try {
      const [
        alertsRes, incRes, eventsRes, malwareRes,
        rulesRes, vulnRes, hpRes, dashRes,
        hpAttackersRes, hpStatsRes,
      ] = await Promise.allSettled([
        networkApi.getAlerts("", 0, 100),
        incApi.getAll("", "", 0, 50),
        eventsApi.getEvents("", "", 0, 100),
        malwareApi.getScans("", 0, 50),
        networkApi.getRules(),
        vulnApi.getFindings("", "", 0, 100),
        hpApi.getAll(),
        dashApi.stats(),
        hpApi.getAttackers(50),
        hpApi.getStats(),
      ]);

      const extract = (r, fallback = []) =>
        r.status === "fulfilled"
          ? (r.value?.content ?? r.value ?? fallback)
          : fallback;

      setData(p => {
        const mergedAlerts = extract(alertsRes, p.alerts);
        const seededFeed = (p.feedItems && p.feedItems.length > 0)
          ? p.feedItems
          : mergedAlerts.slice(0, 20).map(a => ({
              time: fmtTime(a.timestamp || Date.now()),
              severity: normalizeFeedSeverity(a.severity),
              label: a.alertType || "ALERT",
              message: a.alertMessage || a.message || "Alert event",
            }));

        return {
          ...p,
          alerts:       mergedAlerts,
          incidents:    extract(incRes,     p.incidents),
          winEvents:    extract(eventsRes,  p.winEvents),
          malwareScans: extract(malwareRes, p.malwareScans),
          idsRules:     extract(rulesRes,   p.idsRules),
          vulnFindings: extract(vulnRes,    p.vulnFindings),
          honeypots:    extract(hpRes,      p.honeypots),
          dashStats:    dashRes.status === "fulfilled" ? dashRes.value : p.dashStats,
          attackers:    extract(hpAttackersRes, p.attackers),
          honeypotStats: hpStatsRes.status === "fulfilled" ? hpStatsRes.value : p.honeypotStats,
          feedItems: seededFeed.slice(0, FEED_MAX),
        };
      });
    } catch (e) {
      console.error("[sync] REST sync error:", e);
    }
  }, [authState.connected]);

  // ── Auto-start sync when connected ──────────────────────────────
  useEffect(() => {
    if (!authState.connected) {
      clearInterval(syncTimerRef.current);
      return;
    }
    syncAll();
    syncTimerRef.current = setInterval(syncAll, SYNC_MS);
    return () => clearInterval(syncTimerRef.current);
  }, [authState.connected, syncAll]);

  // ── Health check loop ───────────────────────────────────────────
  const checkHealth = useCallback(async () => {
    if (!authState.connected) return;
    try {
      const mlStatus = await mlApi.health().catch(() => null);
      patchAuth({ mlOnline: !!mlStatus });
      setData(p => ({ ...p, mlStatus }));
    } catch {}
  }, [authState.connected, patchAuth]);

  useEffect(() => {
    if (!authState.connected) return;
    checkHealth();
    healthTimerRef.current = setInterval(checkHealth, HEALTH_MS);
    return () => clearInterval(healthTimerRef.current);
  }, [authState.connected, checkHealth]);

  // ── Cleanup ──────────────────────────────────────────────────────
  useEffect(() => () => {
    clearInterval(syncTimerRef.current);
    clearInterval(healthTimerRef.current);
  }, []);

  // ════════════════════════════════════════════════════════════════
  //  ACTIONS  — all call real backend, all throw on error
  // ════════════════════════════════════════════════════════════════
  const actions = {

    // ── Login (MUST succeed before app loads) ──────────────────────
    login: async (username, password) => {
      patchAuth({ loading: true, error: null });
      try {
        const loginData = await authApi.login(username, password);
        setToken(loginData.accessToken);

        // Connect WebSocket with JWT
        ws.connect(loginData.accessToken);

        // Check ML service
        const mlStatus = await mlApi.health().catch(() => null);

        patchAuth({
          loading:   false,
          connected: true,
          mlOnline:  !!mlStatus,
          error:     null,
          user:      loginData.user,
        });

        // Auto-start packet capture
        try {
          await networkApi.startCapture();
          setData(p => ({ ...p, captureRunning: true }));
          console.info("[capture] Auto-started packet capture after login");
        } catch (capErr) {
          console.warn("[capture] Auto-start failed (run as Administrator?):", capErr.message);
          patchAuth({ error: null }); // non-fatal: login still succeeds
        }

        return loginData;
      } catch (err) {
        clearToken();
        patchAuth({
          loading:   false,
          connected: false,
          error:     err.message || "Login failed",
        });
        throw err;
      }
    },

    // ── Logout ──────────────────────────────────────────────────────
    logout: async () => {
      try { await authApi.logout(); } catch {}
      try { await networkApi.stopCapture(); } catch {}
      ws.disconnect();
      clearToken();
      clearInterval(syncTimerRef.current);
      clearInterval(healthTimerRef.current);
      patchAuth({ connected:false, loading:false, error:null, user:null });
      setData(p => ({ ...p, captureRunning:false }));
    },

    // ── Capture ──────────────────────────────────────────────────────
    startCapture: async () => {
      const res = await networkApi.startCapture();
      patch({ captureRunning: true });
      return res;
    },
    stopCapture: async () => {
      const res = await networkApi.stopCapture();
      patch({ captureRunning: false });
      return res;
    },
    toggleCapture: async () => {
      if (data.captureRunning) return actions.stopCapture();
      return actions.startCapture();
    },
    listInterfaces: () => networkApi.listInterfaces(),

    // ── IDS Rules ────────────────────────────────────────────────────
    createRule: async (rule) => {
      const created = await networkApi.createRule(rule);
      setData(p => ({ ...p, idsRules: [...p.idsRules, created] }));
      return created;
    },
    deleteRule: async (id) => {
      await networkApi.deleteRule(id);
      setData(p => ({ ...p, idsRules: p.idsRules.filter(r => r.ruleId !== id) }));
    },
    toggleRule: async (id) => {
      const rule    = data.idsRules.find(r => r.ruleId === id);
      const updated = await networkApi.toggleRule(id, !rule?.active);
      setData(p => ({ ...p, idsRules: p.idsRules.map(r => r.ruleId === id ? { ...r, ...updated } : r) }));
      return updated;
    },
    updateAlertStatus: async (id, status) => {
      const updated = await networkApi.updateAlertStatus(id, status);
      setData(p => ({ ...p, alerts: p.alerts.map(a => a.alertId === id ? { ...a, ...updated, status } : a) }));
      return updated;
    },

    // ── Incidents ────────────────────────────────────────────────────
    createIncident: async (incData) => {
      const created = await incApi.create(incData);
      setData(p => ({ ...p, incidents: [created, ...p.incidents] }));
      return created;
    },
    updateIncident: async (id, status) => {
      const updated = await incApi.updateStatus(id, status);
      setData(p => ({ ...p, incidents: p.incidents.map(i => i.incidentId === id ? { ...i, ...updated, status } : i) }));
      return updated;
    },
    addNote: async (id, note) => {
      return incApi.addNote(id, note);
    },

    // ── Malware scan (with ML enrichment) ───────────────────────────
    scanFile: async (filePath) => {
      // Backend YARA + heuristic scan
      const scan = await malwareApi.scanFile(filePath);

      // ML enrichment if service is online
      if (authState.mlOnline && scan) {
        try {
          const mlFeatures = buildMlTestFeatures(scan);
          const mlResult = await mlApi.analyzeFile({
            fileName:     scan.fileName,
            fileSize:     scan.fileSize,
            fileHash:     scan.fileHash,
            features:     mlFeatures,
            payloadSample: "",
          });
          scan._mlVerdict = mlResult;
          scan._mlFeatures = mlFeatures;
        } catch {}
      }

      setData(p => ({ ...p, malwareScans: [scan, ...p.malwareScans] }));
      return scan;
    },
    startMalwareFullScan: async (rootPath = "") => {
      return malwareApi.startFullScan(rootPath);
    },
    getMalwareFullScanStatus: async (jobId) => {
      return malwareApi.getFullScanStatus(jobId);
    },
    stopMalwareFullScan: async (jobId) => {
      return malwareApi.stopFullScan(jobId);
    },

    // ── Vulnerability ────────────────────────────────────────────────
    createScan: async (scanData) => {
      const scan = await vulnApi.createScan(scanData.name, scanData.type, scanData.targets);
      await syncAll();
      return scan;
    },
    startContinuousInterfaceScan: async (payload) => {
      const result = await vulnApi.startContinuousInterfaceScan(
        payload.interfaceName,
        payload.intervalSeconds,
        payload.name || ""
      );
      await syncAll();
      return result;
    },
    getScanRuntimeStatus: async (scanId) => {
      return vulnApi.getScanRuntime(scanId);
    },
    stopScanRuntime: async (scanId) => {
      const result = await vulnApi.stopScanRuntime(scanId);
      await syncAll();
      return result;
    },
    updateFinding: async (id, status) => {
      const updated = await vulnApi.updateFinding(id, status);
      setData(p => ({ ...p, vulnFindings: p.vulnFindings.map(f => f.findingId === id ? { ...f, ...updated, status } : f) }));
      return updated;
    },

    // ── Honeypots ────────────────────────────────────────────────────
    deployHoneypot: async (d) => {
      const hp = await hpApi.deploy(d.name, d.type, d.ip, d.port);
      setData(p => ({ ...p, honeypots: [...p.honeypots, hp] }));
      return hp;
    },
    toggleHoneypot: async (id) => {
      const hp = data.honeypots.find(h => h.honeypotId === id);
      if (hp?.active) await hpApi.deactivate(id);
      setData(p => ({ ...p, honeypots: p.honeypots.map(h => h.honeypotId === id ? { ...h, active: !h.active } : h) }));
    },

    // ── Users ─────────────────────────────────────────────────────────
    addUser: async (userData) => {
      const created = await authApi.register(userData);
      await syncAll(); // refresh user list
      return created;
    },

    // Force manual sync
    syncAll,
  };

  return { authState, data, actions };
}
