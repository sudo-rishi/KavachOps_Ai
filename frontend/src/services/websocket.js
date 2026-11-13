// ═══════════════════════════════════════════════════════════════
//  KavachOps AI WebSocket Service
//  STOMP over SockJS → Spring Boot /api/ws
//  Topics mirrored from AlertBroadcaster.java
// ═══════════════════════════════════════════════════════════════

import { Client } from "@stomp/stompjs";
import SockJS from "sockjs-client/dist/sockjs";
import { API_BASE } from "../api/client.js";

export const TOPICS = {
  ALERTS:    "/topic/alerts",
  TRAFFIC:   "/topic/traffic",
  EVENTS:    "/topic/events",
  INCIDENTS: "/topic/incidents",
  DASHBOARD: "/topic/dashboard",
  MALWARE:   "/topic/malware",
  HONEYPOT:  "/topic/honeypot",
};

const env = import.meta?.env || {};

function resolveWsUrl() {
  if (env.VITE_WS_URL) return env.VITE_WS_URL;

  if (/^https?:\/\//i.test(API_BASE)) {
    const origin = API_BASE.replace(/\/api\/?$/, "");
    return `${origin}/api/ws`;
  }

  return `${window.location.origin}/api/ws`;
}

const WS_URL          = resolveWsUrl();
const RECONNECT_BASE  = 2000;
const MAX_ATTEMPTS    = 12;

class WsService {
  constructor() {
    this._stompClient   = null;
    this._connected     = false;
    this._connecting    = false;
    this._token         = null;
    this._attempts      = 0;
    this._reconnTimer   = null;
    this._subs          = new Map();   // topic → Set<fn>
    this._statusCbs     = new Set();
    this._brokerSubs    = new Map();   // topic → stomp subscription object
  }

  // ── Public ────────────────────────────────────────────────────
  connect(token) {
    this._token    = token;
    this._attempts = 0;
    this._tryConnect();
  }

  disconnect() {
    this._attempts = MAX_ATTEMPTS;
    clearTimeout(this._reconnTimer);
    this._brokerSubs.clear();
    if (this._stompClient) {
      try { this._stompClient.deactivate(); } catch {}
      this._stompClient = null;
    }
    this._connected  = false;
    this._connecting = false;
    this._emit("disconnected");
  }

  /** Subscribe to a topic. Returns () => void unsubscribe fn. */
  on(topic, callback) {
    if (!this._subs.has(topic)) this._subs.set(topic, new Set());
    this._subs.get(topic).add(callback);

    if (this._connected) this._bindTopic(topic);

    return () => {
      const s = this._subs.get(topic);
      if (s) { s.delete(callback); if (s.size === 0) this._subs.delete(topic); }
    };
  }

  /** Listen for status: "connecting"|"connected"|"disconnected"|"failed" */
  onStatus(cb) {
    this._statusCbs.add(cb);
    cb(this._connected ? "connected" : "disconnected");
    return () => this._statusCbs.delete(cb);
  }

  isConnected()  { return this._connected; }
  getAttempts()  { return this._attempts;  }

  // ── Internal ──────────────────────────────────────────────────
  _tryConnect() {
    if (this._connecting || this._connected) return;
    if (this._attempts >= MAX_ATTEMPTS) { this._emit("failed"); return; }

    this._connecting = true;
    this._emit("connecting");

    const headers = this._token ? { Authorization: `Bearer ${this._token}` } : {};

    this._stompClient = new Client({
      webSocketFactory: () => new SockJS(WS_URL),
      connectHeaders:   headers,
      heartbeatIncoming: 4000,
      heartbeatOutgoing: 4000,
      reconnectDelay:    0,

      onConnect: () => {
        this._connected  = true;
        this._connecting = false;
        this._attempts   = 0;
        this._emit("connected");

        // Re-bind all pending subscriptions
        for (const topic of this._subs.keys()) this._bindTopic(topic);
      },

      onDisconnect: () => {
        this._connected  = false;
        this._connecting = false;
        this._brokerSubs.clear();
        this._emit("disconnected");
        this._scheduleReconnect();
      },

      onStompError: (frame) => {
        this._connected  = false;
        this._connecting = false;
        this._emit("disconnected");
        console.error("[WS] STOMP error:", frame.headers?.message);
        this._scheduleReconnect();
      },

      onWebSocketClose: () => {
        if (this._connected || this._connecting) {
          this._connected  = false;
          this._connecting = false;
          this._brokerSubs.clear();
          this._emit("disconnected");
          this._scheduleReconnect();
        }
      },
    });

    try {
      this._stompClient.activate();
    } catch (e) {
      this._connecting = false;
      this._scheduleReconnect();
    }
  }

  _bindTopic(topic) {
    if (!this._connected || !this._stompClient) return;
    if (this._brokerSubs.has(topic)) return; // already subscribed

    const sub = this._stompClient.subscribe(topic, (msg) => {
      try {
        const data = JSON.parse(msg.body);
        const cbs  = this._subs.get(topic);
        if (cbs) cbs.forEach(cb => { try { cb(data); } catch {} });
      } catch {}
    });
    this._brokerSubs.set(topic, sub);
  }

  _scheduleReconnect() {
    this._attempts++;
    if (this._attempts >= MAX_ATTEMPTS) { this._emit("failed"); return; }
    const delay = Math.min(RECONNECT_BASE * this._attempts, 30000);
    console.info(`[WS] Reconnecting in ${(delay/1000).toFixed(1)}s (attempt ${this._attempts}/${MAX_ATTEMPTS})`);
    this._reconnTimer = setTimeout(() => this._tryConnect(), delay);
  }

  _emit(status) {
    this._statusCbs.forEach(cb => { try { cb(status); } catch {} });
  }
}

// Singleton export
export const ws = new WsService();
