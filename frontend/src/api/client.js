// Shield-God REST API Client
// Change VITE_API_BASE in .env.local for cross-machine deployment

const env = import.meta?.env || {};

function normalizeBaseUrl(value, fallback) {
  const base = (value || fallback || "").trim();
  if (!base) return fallback;
  return base.replace(/\/$/, "");
}

export const API_BASE = normalizeBaseUrl(env.VITE_API_BASE, "/api");
export const ML_BASE  = normalizeBaseUrl(env.VITE_ML_BASE, "http://localhost:5000");

const TOKEN_KEY = "shieldgod.accessToken";
let _token = null;

try {
  _token = localStorage.getItem(TOKEN_KEY);
} catch {
  _token = null;
}

export const setToken = (t) => {
  _token = t || null;
  try {
    if (_token) localStorage.setItem(TOKEN_KEY, _token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    // Ignore storage failures and continue with in-memory token.
  }
};

export const getToken = () => _token;

export const clearToken = () => {
  _token = null;
  try {
    localStorage.removeItem(TOKEN_KEY);
  } catch {
    // Ignore storage failures.
  }
};

export class ApiError extends Error {
  constructor(status, message, data) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.data   = data;
  }
}

async function call(path, options = {}, base = API_BASE) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (_token) headers["Authorization"] = `Bearer ${_token}`;
  const res = await fetch(`${base}${path}`, {
    ...options, headers,
    signal: AbortSignal.timeout(options.timeout || 10000),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(res.status, body.message || body.error || res.statusText, body);
  }
  if (res.status === 204) return null;
  return res.json();
}

async function callBlob(path, options = {}, base = API_BASE) {
  const headers = { ...(options.headers || {}) };
  if (_token) headers["Authorization"] = `Bearer ${_token}`;

  const res = await fetch(`${base}${path}`, {
    ...options,
    headers,
    signal: AbortSignal.timeout(options.timeout || 20000),
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(res.status, body.message || body.error || res.statusText, body);
  }

  const blob = await res.blob();
  const contentDisposition = res.headers.get("content-disposition") || "";
  const fileNameMatch = /filename\*?=(?:UTF-8''|\")?([^\";]+)/i.exec(contentDisposition);
  const fileName = fileNameMatch ? decodeURIComponent(fileNameMatch[1].replace(/"/g, "")) : null;

  return { blob, fileName };
}

export async function checkHealth() {
  const res = await fetch(`${API_BASE}/actuator/health`, { signal: AbortSignal.timeout(4000) });
  if (!res.ok) throw new ApiError(res.status, "Backend health check failed");
  const body = await res.json();
  if (body.status !== "UP") throw new ApiError(503, `Backend status: ${body.status}`);
  return body;
}

export async function checkMlHealth() {
  const res = await fetch(`${ML_BASE}/api/health`, { signal: AbortSignal.timeout(4000) });
  if (!res.ok) throw new ApiError(res.status, "ML service unavailable");
  return res.json();
}

export const auth = {
  login:    (username, password) => call("/auth/login",    { method:"POST", body: JSON.stringify({ username, password }) }),
  logout:   ()                   => call("/auth/logout",   { method:"POST" }),
  me:       ()                   => call("/auth/me"),
  refresh:  (rt)                 => call("/auth/refresh",  { method:"POST", body: JSON.stringify({ refreshToken: rt }) }),
  register: (data)               => call("/auth/register", { method:"POST", body: JSON.stringify(data) }),
};

export const dashboard = { stats: () => call("/dashboard/stats") };

export const network = {
  startCapture:     ()               => call("/network/capture/start",   { method:"POST" }),
  stopCapture:      ()               => call("/network/capture/stop",    { method:"POST" }),
  captureStatus:    ()               => call("/network/capture/status"),
  listInterfaces:   ()               => call("/network/capture/interfaces"),
  getTraffic:       (p=0,s=50)       => call(`/network/traffic?page=${p}&size=${s}`),
  getAlerts:        (st="",p=0,s=50) => call(`/network/alerts?status=${st}&page=${p}&size=${s}`),
  updateAlertStatus:(id,status)      => call(`/network/alerts/${id}/status`,    { method:"PATCH", body: JSON.stringify({ status }) }),
  getStats:         ()               => call("/network/stats"),
  getRules:         ()               => call("/network/rules"),
  createRule:       (rule)           => call("/network/rules",                  { method:"POST",  body: JSON.stringify(rule) }),
  deleteRule:       (id)             => call(`/network/rules/${id}`,            { method:"DELETE" }),
  toggleRule:       (id,active)      => call(`/network/rules/${id}/toggle`,     { method:"PATCH", body: JSON.stringify({ active }) }),
};

export const events = {
  getEvents:         (ch="",lv="",p=0,s=50) => call(`/events?channel=${ch}&level=${lv}&page=${p}&size=${s}`),
  getStats:          ()                      => call("/events/stats"),
  getSecurityEvents: (limit=50)              => call(`/events/security?limit=${limit}`),
  readerStatus:      ()                      => call("/events/reader/status"),
  getCatalogStatus:  ()                      => call("/events/catalog/status"),
  getCatalogEntry:   (eventId)               => call(`/events/catalog/${eventId}`),
};

export const malware = {
  scanFile: (filePath)          => call("/malware/scan",  { method:"POST", body: JSON.stringify({ filePath }), timeout:60000 }),
  getScans: (res="",p=0,s=50)   => call(`/malware/scans?result=${res}&page=${p}&size=${s}`),
  getStats: ()                  => call("/malware/stats"),
  startFullScan: (rootPath = "") => call("/malware/scan/full", {
    method: "POST",
    body: JSON.stringify(rootPath ? { rootPath } : {}),
    timeout: 20000,
  }),
  getFullScanStatus: (jobId)     => call(`/malware/scan/full/${jobId}`),
  stopFullScan: (jobId)          => call(`/malware/scan/full/${jobId}/stop`, { method: "POST" }),
};

export const incidents = {
  getAll:       (st="",sv="",p=0,s=20) => call(`/incidents?status=${st}&severity=${sv}&page=${p}&size=${s}`),
  getById:      (id)                    => call(`/incidents/${id}`),
  getTimeline:  (id)                    => call(`/incidents/${id}/timeline`),
  getStats:     ()                      => call("/incidents/stats"),
  create:       (data)                  => call("/incidents",             { method:"POST",  body: JSON.stringify(data) }),
  updateStatus: (id,status)             => call(`/incidents/${id}/status`,{ method:"PATCH", body: JSON.stringify({ status }) }),
  addNote:      (id,note)               => call(`/incidents/${id}/notes`, { method:"POST",  body: JSON.stringify({ note }) }),
};

export const vulnerability = {
  createScan:    (name,type,targets)    => call("/vulnerability/scans",               { method:"POST",  body: JSON.stringify({ name, type, targets }) }),
  startContinuousInterfaceScan: (interfaceName, intervalSeconds = 120, name = "") =>
    call("/vulnerability/scans/interface/continuous", {
      method: "POST",
      body: JSON.stringify({ interfaceName, intervalSeconds, name }),
    }),
  getScanRuntime: (scanId)              => call(`/vulnerability/scans/${scanId}/runtime`),
  stopScanRuntime: (scanId)             => call(`/vulnerability/scans/${scanId}/stop`, { method: "POST" }),
  getScans:      (p=0,s=20)            => call(`/vulnerability/scans?page=${p}&size=${s}`),
  getFindings:   (sv="",st="",p=0,s=50)=> call(`/vulnerability/findings?severity=${sv}&status=${st}&page=${p}&size=${s}`),
  updateFinding: (id,status)           => call(`/vulnerability/findings/${id}/status`,{ method:"PATCH", body: JSON.stringify({ status }) }),
  getStats:      ()                    => call("/vulnerability/stats"),
};

export const reports = {
  syncData: ({ days = 30, limit = 1000 } = {}) => {
    const params = new URLSearchParams();
    params.set("days", String(days));
    params.set("limit", String(limit));
    return call(`/reports/sync?${params.toString()}`);
  },
  downloadVulnerabilityPdf: ({ severity = "", status = "", from = "", to = "" } = {}) => {
    const params = new URLSearchParams();
    if (severity) params.set("severity", severity);
    if (status) params.set("status", status);
    if (from) params.set("from", from);
    if (to) params.set("to", to);
    const query = params.toString();
    return callBlob(`/reports/vulnerability/pdf${query ? `?${query}` : ""}`);
  },
};

export const honeypots = {
  getAll:          ()                           => call("/honeypots"),
  deploy:          (name,type,ipAddress,port)   => call("/honeypots",         { method:"POST",   body: JSON.stringify({ name, type, ipAddress, port }) }),
  deactivate:      (id)                         => call(`/honeypots/${id}`,   { method:"DELETE" }),
  getInteractions: (p=0,s=50)                   => call(`/honeypots/interactions?page=${p}&size=${s}`),
  getAttackers:    (limit=20)                   => call(`/honeypots/attackers?limit=${limit}`),
  getStats:        ()                           => call("/honeypots/stats"),
};

export const ml = {
  health:        ()             => checkMlHealth(),
  detectAnomaly: (record)       => call("/api/anomaly/detect",  { method:"POST", body: JSON.stringify(record),           timeout:12000 }, ML_BASE),
  batchAnomaly:  (records)      => call("/api/anomaly/batch",   { method:"POST", body: JSON.stringify({ records }),       timeout:20000 }, ML_BASE),
  analyzeFile:   (fileInfo)     => call("/api/malware/analyze", { method:"POST", body: JSON.stringify(fileInfo),          timeout:20000 }, ML_BASE),
  retrain:       (t,s,l)        => call("/api/model/retrain",   { method:"POST", body: JSON.stringify({type:t,samples:s,labels:l}), timeout:30000 }, ML_BASE),
};
