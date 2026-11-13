package com.kavachopsai.controller;

import java.time.ZonedDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.kavachopsai.capture.PacketCaptureEngine;
import com.kavachopsai.service.IncidentService;
import com.kavachopsai.service.MalwareDetectionService;
import com.kavachopsai.service.NetworkAnalysisService;
import com.kavachopsai.service.WindowsEventService;
import com.kavachopsai.websocket.AlertBroadcaster;
import com.kavachopsai.windows.WindowsEventLogReader;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/dashboard")
@RequiredArgsConstructor
public class DashboardController {

    @Value("${spring.application.name:KavachOps Ai}")
    private String appName;

    @Value("${kavachopsai.app.version:1.0.0}")
    private String appVersion;

    private final NetworkAnalysisService networkService;
    private final WindowsEventService eventService;
    private final IncidentService incidentService;
    private final MalwareDetectionService malwareService;
    private final PacketCaptureEngine captureEngine;
    private final WindowsEventLogReader eventReader;
    private final AlertBroadcaster broadcaster;

    /**
     * Returns a single aggregated stats object for the dashboard.
     */
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getDashboardStats() {
        return ResponseEntity.ok(buildStats());
    }

    @GetMapping("/version")
    public ResponseEntity<Map<String, Object>> getVersionInfo() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("name", appName);
        payload.put("version", appVersion);
        payload.put("javaVersion", System.getProperty("java.version"));
        payload.put("timestamp", ZonedDateTime.now().toString());
        return ResponseEntity.ok(payload);
    }

    /**
     * Scheduled broadcast of dashboard stats every 10 seconds via WebSocket.
     */
    @Scheduled(fixedDelay = 10_000)
    public void broadcastDashboardStats() {
        try {
            broadcaster.broadcastDashboardUpdate(buildStats());
        } catch (Exception e) {
            // Non-critical, don't let scheduler die
        }
    }

    private Map<String, Object> buildStats() {
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("timestamp", ZonedDateTime.now().toString());

        // Capture engine status
        stats.put("capture", Map.of(
            "running",   captureEngine.isRunning(),
            "interface", captureEngine.getActiveInterface() != null ? captureEngine.getActiveInterface() : "none",
            "packets",   captureEngine.getPacketCount(),
            "loops",     captureEngine.getCaptureLoopCount(),
            "restarts",  captureEngine.getRestartCount(),
            "lastLoopAt", String.valueOf(captureEngine.getLastLoopStartedAt()),
            "lastPacketAt", String.valueOf(captureEngine.getLastPacketAt())
        ));

        // Windows event reader status
        stats.put("eventReader", Map.of(
            "running", eventReader.isRunning()
        ));

        // Network & IDS stats
        try { stats.put("network", networkService.getAlertStats()); }
        catch (Exception e) { stats.put("network", Map.of("error", e.getMessage())); }

        // Windows event stats
        try { stats.put("events", eventService.getEventStats()); }
        catch (Exception e) { stats.put("events", Map.of("error", e.getMessage())); }

        // Incident stats
        try { stats.put("incidents", incidentService.getIncidentStats()); }
        catch (Exception e) { stats.put("incidents", Map.of("error", e.getMessage())); }

        // Malware stats
        try { stats.put("malware", malwareService.getMalwareStats()); }
        catch (Exception e) { stats.put("malware", Map.of("error", e.getMessage())); }
        try { stats.put("malwareFilesystem", malwareService.getFileSystemRuntimeStats()); }
        catch (Exception e) { stats.put("malwareFilesystem", Map.of("error", e.getMessage())); }

        return stats;
    }
}

