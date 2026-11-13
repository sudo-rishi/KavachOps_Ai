package com.kavachopsai.controller;

import java.util.List;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.kavachopsai.capture.PacketCaptureEngine;
import com.kavachopsai.model.IdsRule;
import com.kavachopsai.service.NetworkAnalysisService;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/network")
@RequiredArgsConstructor
public class NetworkController {

    private final NetworkAnalysisService networkService;
    private final PacketCaptureEngine captureEngine;

    // â”€â”€â”€ Capture Control â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    @PostMapping("/capture/start")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
    public ResponseEntity<Map<String, Object>> startCapture() {
        if (captureEngine.isRunning()) {
            return ResponseEntity.ok(Map.of(
                "status",    "already_running",
                "interface", captureEngine.getActiveInterface(),
                "packets",   captureEngine.getPacketCount(),
                "loops",     captureEngine.getCaptureLoopCount(),
                "restarts",  captureEngine.getRestartCount()
            ));
        }
        captureEngine.startCapture();
        return ResponseEntity.ok(Map.of("status", "starting", "message", "Packet capture initiated"));
    }

    @PostMapping("/capture/stop")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
    public ResponseEntity<Map<String, Object>> stopCapture() {
        captureEngine.stopCapture();
        return ResponseEntity.ok(Map.of(
            "status",  "stopped",
            "packets", captureEngine.getPacketCount(),
            "loops",   captureEngine.getCaptureLoopCount(),
            "restarts", captureEngine.getRestartCount()
        ));
    }

    @GetMapping("/capture/status")
    public ResponseEntity<Map<String, Object>> captureStatus() {
        return ResponseEntity.ok(Map.of(
            "running",   captureEngine.isRunning(),
            "interface", captureEngine.getActiveInterface() != null ? captureEngine.getActiveInterface() : "none",
            "packets",   captureEngine.getPacketCount(),
            "loops",     captureEngine.getCaptureLoopCount(),
            "restarts",  captureEngine.getRestartCount()
        ));
    }

    @GetMapping("/capture/interfaces")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    public ResponseEntity<List<String>> listInterfaces() {
        return ResponseEntity.ok(captureEngine.listAvailableInterfaces());
    }

    // â”€â”€â”€ Traffic â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    @GetMapping("/traffic")
    public ResponseEntity<?> getTraffic(
            @RequestParam(defaultValue = "0")  int page,
            @RequestParam(defaultValue = "50") int size) {
        return ResponseEntity.ok(networkService.getRecentTraffic(page, size));
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        return ResponseEntity.ok(networkService.getAlertStats());
    }

    // â”€â”€â”€ Alerts â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    @GetMapping("/alerts")
    public ResponseEntity<?> getAlerts(
            @RequestParam(required = false) String status,
            @RequestParam(defaultValue = "0")  int page,
            @RequestParam(defaultValue = "50") int size) {
        return ResponseEntity.ok(networkService.getAlerts(status, page, size));
    }

    @PatchMapping("/alerts/{id}/status")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
    public ResponseEntity<?> updateAlertStatus(
            @PathVariable Long id,
            @RequestBody Map<String, String> body) {
        return ResponseEntity.ok(networkService.updateAlertStatus(id, body.get("status")));
    }

    // â”€â”€â”€ IDS Rules â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    @GetMapping("/rules")
    public ResponseEntity<List<IdsRule>> getRules() {
        return ResponseEntity.ok(networkService.getAllRules());
    }

    @PostMapping("/rules")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    public ResponseEntity<IdsRule> createRule(@Valid @RequestBody IdsRuleRequest req) {
        IdsRule rule = IdsRule.builder()
                .ruleName(req.getRuleName())
                .ruleContent(req.getRuleContent())
                .ruleType(req.getRuleType())
                .severity(req.getSeverity())
                .sourceIpPattern(req.getSourceIpPattern())
                .destIpPattern(req.getDestIpPattern())
                .portPattern(req.getPortPattern())
                .protocolPattern(req.getProtocolPattern())
                .payloadPattern(req.getPayloadPattern())
                .active(true)
                .build();
        return ResponseEntity.ok(networkService.createRule(rule));
    }

    @DeleteMapping("/rules/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> deleteRule(@PathVariable Long id) {
        networkService.deleteRule(id);
        return ResponseEntity.ok(Map.of("message", "Rule deleted"));
    }

    @PatchMapping("/rules/{id}/toggle")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    public ResponseEntity<IdsRule> toggleRule(
            @PathVariable Long id,
            @RequestBody Map<String, Boolean> body) {
        return ResponseEntity.ok(networkService.toggleRule(id, body.getOrDefault("active", true)));
    }

    // â”€â”€â”€ DTO â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    @Data static class IdsRuleRequest {
        @NotBlank String ruleName;
        @NotBlank String ruleContent;
        @NotBlank String ruleType;
        int severity = 2;
        String sourceIpPattern;
        String destIpPattern;
        String portPattern;
        String protocolPattern;
        String payloadPattern;
    }
}

