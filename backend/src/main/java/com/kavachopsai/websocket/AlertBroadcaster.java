package com.kavachopsai.websocket;

import java.time.ZonedDateTime;
import java.util.Map;

import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Component;

import com.kavachopsai.model.Incident;
import com.kavachopsai.model.NetworkAlert;
import com.kavachopsai.model.NetworkTraffic;
import com.kavachopsai.model.WindowsEventLog;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Broadcasts real-time security events to connected frontend clients via WebSocket/STOMP.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AlertBroadcaster {

    private final SimpMessagingTemplate messagingTemplate;

    /** Broadcast a new IDS/anomaly alert */
    public void broadcastAlert(NetworkAlert alert) {
        try {
            var payload = Map.of(
                "alertId",       alert.getAlertId() != null ? alert.getAlertId() : 0L,
                "severity",      alert.getSeverity(),
                "sourceIp",      alert.getSourceIp(),
                "destinationIp", alert.getDestinationIp(),
                "protocol",      orEmpty(alert.getProtocol()),
                "message",       orEmpty(alert.getAlertMessage()),
                "alertType",     orEmpty(alert.getAlertType()),
                "timestamp",     alert.getTimestamp().toString(),
                "status",        alert.getStatus()
            );
            messagingTemplate.convertAndSend("/topic/alerts", payload);
        } catch (Exception e) {
            log.trace("Alert broadcast error: {}", e.getMessage());
        }
    }

    /** Broadcast live packet metadata (not full payload for security/perf) */
    public void broadcastTraffic(NetworkTraffic traffic) {
        try {
            var payload = Map.of(
                "sourceIp",      traffic.getSourceIp(),
                "destinationIp", traffic.getDestinationIp(),
                "protocol",      orEmpty(traffic.getProtocol()),
                "sourcePort",    traffic.getSourcePort() != null ? traffic.getSourcePort() : 0,
                "destPort",      traffic.getDestinationPort() != null ? traffic.getDestinationPort() : 0,
                "packetSize",    traffic.getPacketSize() != null ? traffic.getPacketSize() : 0,
                "timestamp",     traffic.getTimestamp().toString()
            );
            messagingTemplate.convertAndSend("/topic/traffic", payload);
        } catch (Exception e) {
            log.trace("Traffic broadcast error: {}", e.getMessage());
        }
    }

    /** Broadcast a Windows Event Log entry */
    public void broadcastWindowsEvent(WindowsEventLog event) {
        try {
            var payload = Map.of(
                "eventId",          event.getEventId(),
                "channel",          event.getChannel(),
                "level",            event.getLevel(),
                "source",           orEmpty(event.getSource()),
                "computerName",     orEmpty(event.getComputerName()),
                "message",          orEmpty(event.getMessage()),
                "securityRelevant", event.isSecurityRelevant(),
                "eventTime",        event.getEventTime().toString()
            );
            messagingTemplate.convertAndSend("/topic/events", payload);
        } catch (Exception e) {
            log.trace("Event broadcast error: {}", e.getMessage());
        }
    }

    /** Broadcast a new or updated incident */
    public void broadcastIncident(Incident incident) {
        try {
            var payload = Map.of(
                "incidentId",     incident.getIncidentId(),
                "incidentNumber", incident.getIncidentNumber(),
                "title",          incident.getTitle(),
                "severity",       incident.getSeverity(),
                "status",         incident.getStatus(),
                "createdAt",      incident.getCreatedAt().toString()
            );
            messagingTemplate.convertAndSend("/topic/incidents", payload);
        } catch (Exception e) {
            log.trace("Incident broadcast error: {}", e.getMessage());
        }
    }

    /** Broadcast dashboard stats update */
    public void broadcastDashboardUpdate(Map<String, Object> stats) {
        try {
            messagingTemplate.convertAndSend("/topic/dashboard", (Object) stats);
        } catch (Exception e) {
            log.trace("Dashboard broadcast error: {}", e.getMessage());
        }
    }

    /** Broadcast a system notification */
    public void broadcastSystemNotification(String level, String message) {
        try {
            var payload = Map.of(
                "level",     level,
                "message",   message,
                "timestamp", ZonedDateTime.now().toString()
            );
            messagingTemplate.convertAndSend("/topic/alerts", payload);
        } catch (Exception e) {
            log.trace("Notification broadcast error: {}", e.getMessage());
        }
    }

    private String orEmpty(String s) { return s != null ? s : ""; }
}

