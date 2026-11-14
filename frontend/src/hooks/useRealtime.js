// ═══════════════════════════════════════════════════════════════
//  useRealtime — Manages all live data from Shield-God backend
//  • Polls REST every SYNC_MS for bulk data
//  • Receives WebSocket pushes for real-time updates
//  • Auto-starts packet capture after login
//  • Enriches alerts with ML anomaly scores
//  • Empty modules show clearly marked, frontend-only demo examples
// ═══════════════════════════════════════════════════════════════

import { useState, useEffect, useRef, useCallback } from "react";
import {
  setToken, clearToken, getToken,
  checkHealth,
  auth as authApi,
  network  as networkApi,
  events   as eventsApi,
  malware  as malwareApi,
  incidents as incApi,
  vulnerability as vulnApi,
  honeypots as hpApi,
  dashboard as dashApi,
  ml        as mlApi,
  users     as usersApi,
} from "../api/client.js";
import { ws, TOPICS } from "../services/websocket.js";
import { fmtTime } from "../utils/dateFormatter.js";
import { createDemoData } from "../data/seed.js";

const SYNC_MS   = 15_000;   // REST sync interval
const HEALTH_MS = 10_000;   // health check interval
const FEED_MAX = 60;
const TRAFFIC_FEED_INTERVAL = 25;

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
    mlError:        null,
    demoDataModules: [],
  });

  const syncTimerRef   = useRef(null);
  const healthTimerRef = useRef(null);
  const pktCountRef    = useRef(0);
  const lastMlCallRef  = useRef(0);

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
        setData(p => ({ ...p, mlStatus }));

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
      setData(p => ({ ...p, mlError: null }));
      return result;
    } catch (error) {
      setData(p => ({ ...p, mlError: error.message || "Anomaly analysis failed" }));
      return null;
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
        const now = Date.now();
        const sampledPacket = pktCountRef.current % TRAFFIC_FEED_INTERVAL === 0;
        const rateLimitPassed = now - lastMlCallRef.current >= 1000;
        if (authState.mlOnline && data.mlStatus?.services?.anomaly?.ready && sampledPacket && rateLimitPassed) {
          lastMlCallRef.current = now;
          const ml = await enrichWithMl({
            protocol:      pkt.protocol,
            sourcePort:    pkt.sourcePort,
            destinationPort: pkt.destPort,
            packetSize:    pkt.packetSize,
          });
          anomalyScore = ml?.anomaly_score ?? ml?.anomalyScore ?? null;
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
  }, [authState.mlOnline, data.mlStatus?.services?.anomaly?.ready, enrichWithMl, patchAuth]);

  // ── Full REST sync ───────────────────────────────────────────────
  const syncAll = useCallback(async () => {
    if (!authState.connected) return;
    try {
      const [
        alertsRes, incRes, eventsRes, malwareRes,
        rulesRes, vulnRes, vulnScansRes, hpRes, dashRes,
        hpAttackersRes, hpStatsRes, usersRes,
      ] = await Promise.allSettled([
        networkApi.getAlerts("", 0, 100),
        incApi.getAll("", "", 0, 50),
        eventsApi.getEvents("", "", 0, 100),
        malwareApi.getScans("", 0, 50),
        networkApi.getRules(),
        vulnApi.getFindings("", "", 0, 100),
        vulnApi.getScans(0, 50),
        hpApi.getAll(),
        dashApi.stats(),
        hpApi.getAttackers(50),
        hpApi.getStats(),
        usersApi.getAll(),
      ]);

      const demoData = createDemoData();
      setData(p => {
        const selectRows = (result, previous, sampleRows) => {
          const previousRows = Array.isArray(previous) ? previous : [];
          if (result.status !== "fulfilled") {
            return {
              rows: previousRows,
              seeded: previousRows.some(row => row?._demo === true),
            };
          }

          const responseRows = result.value?.content ?? result.value ?? [];
          const liveRows = Array.isArray(responseRows)
            ? responseRows.filter(row => row?._demo !== true)
            : [];
          if (liveRows.length > 0) return { rows: liveRows, seeded: false };

          const retainedLiveRows = previousRows.filter(row => row?._demo !== true);
          return {
            rows: [...retainedLiveRows, ...sampleRows],
            seeded: sampleRows.length > 0,
          };
        };

        const alerts = selectRows(alertsRes, p.alerts, demoData.alerts);
        const incidents = selectRows(incRes, p.incidents, demoData.incidents);
        const winEvents = selectRows(eventsRes, p.winEvents, demoData.winEvents);
        const malwareScans = selectRows(malwareRes, p.malwareScans, demoData.malwareScans);
        const idsRules = selectRows(rulesRes, p.idsRules, demoData.idsRules);
        const vulnFindings = selectRows(vulnRes, p.vulnFindings, demoData.vulnFindings);
        const vulnScans = selectRows(vulnScansRes, p.vulnScans, demoData.vulnScans);
        const honeypots = selectRows(hpRes, p.honeypots, demoData.honeypots);
        const attackers = selectRows(hpAttackersRes, p.attackers, demoData.attackers);
        const users = selectRows(usersRes, p.users, demoData.users);
        const liveTraffic = (p.trafficFeed || []).filter(row => row?._demo !== true);
        const trafficFeed = liveTraffic.length > 0 ? liveTraffic : demoData.trafficFeed;
        const liveFeedItems = (p.feedItems || []).filter(item => item?._demo !== true);
        const feedItems = liveFeedItems.length > 0
          ? liveFeedItems
          : alerts.rows.slice(0, 20).map(a => ({
              time: fmtTime(a.timestamp || Date.now()),
              severity: normalizeFeedSeverity(a.severity),
              label: a.alertType || "ALERT",
              message: a.alertMessage || a.message || "Alert event",
              ...(a._demo ? { _demo: true } : {}),
            }));

        const demoDataModules = [];
        if (alerts.seeded || idsRules.seeded || trafficFeed.some(row => row._demo)) demoDataModules.push("network");
        if (winEvents.seeded) demoDataModules.push("windows events");
        if (malwareScans.seeded) demoDataModules.push("malware");
        if (incidents.seeded) demoDataModules.push("incidents");
        if (vulnFindings.seeded || vulnScans.seeded) demoDataModules.push("vulnerability");
        if (honeypots.seeded || attackers.seeded) demoDataModules.push("honeypots");
        if (users.seeded) demoDataModules.push("users");

        const reportedHoneypotStats = hpStatsRes.status === "fulfilled" ? hpStatsRes.value : p.honeypotStats;
        const honeypotStats = honeypots.seeded || attackers.seeded
          ? {
              activeHoneypots: honeypots.rows.filter(h => h.active).length,
              interactions24h: honeypots.rows.reduce((total, h) => total + (h.interactions || 0), 0),
              uniqueAttackers24h: attackers.rows.length,
            }
          : reportedHoneypotStats;

        return {
          ...p,
          alerts:       alerts.rows,
          incidents:    incidents.rows,
          winEvents:    winEvents.rows,
          malwareScans: malwareScans.rows,
          idsRules:     idsRules.rows,
          vulnFindings: vulnFindings.rows,
          vulnScans:    vulnScans.rows,
          honeypots:    honeypots.rows,
          dashStats:    dashRes.status === "fulfilled" ? dashRes.value : p.dashStats,
          attackers:    attackers.rows,
          users:        users.rows,
          honeypotStats,
          trafficFeed: trafficFeed.slice(0, 100),
          feedItems: feedItems.slice(0, FEED_MAX),
          demoDataModules,
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
        setData(p => ({ ...p, mlStatus }));

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
    trainAnomalyFromHistory: async () => {
      const trafficPage = await networkApi.getTraffic(0, 500);
      const trafficRows = trafficPage?.content ?? trafficPage ?? [];
      const records = trafficRows.map(packet => ({
        protocol: packet.protocol || "OTHER",
        sourcePort: Number(packet.sourcePort) || 0,
        destinationPort: Number(packet.destinationPort ?? packet.destPort) || 0,
        packetSize: Number(packet.packetSize ?? packet.packetLength ?? packet.size) || 0,
      })).filter(packet => packet.packetSize > 0);

      if (records.length < 20) {
        throw new Error("At least 20 stored traffic records are required to train the anomaly baseline");
      }

      const result = await mlApi.trainAnomaly(records);
      const mlStatus = await mlApi.health();
      patchAuth({ mlOnline: true });
      setData(p => ({ ...p, mlStatus, mlError: null }));
      return result;
    },
    reviewTrafficWithSarvam: async () => {
      const trafficPage = await networkApi.getTraffic(0, 25);
      const trafficRows = trafficPage?.content ?? trafficPage ?? [];
      const records = trafficRows.map(packet => ({
        protocol: packet.protocol || "OTHER",
        sourcePort: Number(packet.sourcePort) || 0,
        destinationPort: Number(packet.destinationPort ?? packet.destPort) || 0,
        packetSize: Number(packet.packetSize ?? packet.packetLength ?? packet.size) || 0,
      })).filter(packet => packet.packetSize > 0);

      if (records.length === 0) {
        throw new Error("No stored traffic records are available for Sarvam review");
      }
      if (!data.mlStatus?.services?.anomaly?.ready) {
        throw new Error("Train the anomaly detector before requesting a Sarvam review");
      }
      return mlApi.batchAnomaly(records);
    },

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

      // Sarvam receives scan metadata only; the deterministic scan verdict remains authoritative.
      if (scan) {
        if (!authState.mlOnline) {
          scan._mlError = "Python ML service is offline";
        } else if (data.mlStatus?.services?.sarvam?.configured !== true) {
          scan._mlError = data.mlStatus?.services?.sarvam?.configured === false
            ? "Sarvam API key is not configured in the Python service"
            : "Sarvam readiness is unavailable; check the ML service status";
        } else {
          try {
            const mlResult = await mlApi.analyzeFile({
              fileName:     scan.fileName,
              fileSize:     scan.fileSize,
              fileHash:     scan.fileHash,
              scanResult:   scan.scanResult,
              threatName:   scan.threatName,
              scanEngine:   scan.scanEngine,
              yaraRuleMatched: scan.yaraRuleMatched,
              virustotalPositives: scan.virustotalPositives,
              virustotalTotal: scan.virustotalTotal,
            });
            scan._mlVerdict = mlResult;
            setData(p => ({ ...p, mlError: null }));
          } catch (error) {
            scan._mlError = error.message || "Sarvam malware assessment failed";
          }
        }
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
    createUser: async (userData) => {
      const created = await usersApi.create(userData);
      setData(p => ({ ...p, users: [...p.users, created] }));
      return created;
    },
    setUserActive: async (userId, active) => {
      const updated = await usersApi.setActive(userId, active);
      setData(p => ({
        ...p,
        users: p.users.map(user => user.userId === userId ? { ...user, ...updated } : user),
      }));
      return updated;
    },

    // Force manual sync
    syncAll,
    retryBackend: async () => {
      try {
        await checkHealth();
        patchAuth({ error: null, connected: false, loading: false });
      } catch (error) {
        patchAuth({ error: error.message || "Backend health check failed", connected: false, loading: false });
        throw error;
      }
    },
  };

  return { authState, data, actions };
}
