package com.kavachopsai.controller;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.kavachopsai.service.HoneypotService;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/honeypots")
@RequiredArgsConstructor
public class HoneypotController {

    private final HoneypotService honeypotService;

    @GetMapping
    public ResponseEntity<?> listHoneypots() {
        return ResponseEntity.ok(honeypotService.getAllHoneypots());
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deployHoneypot(@Valid @RequestBody DeployRequest req) {
        if (!req.isDocker() && (req.getIpAddress() == null || req.getIpAddress().isBlank())) {
            return ResponseEntity.badRequest().body(Map.of("error", "ipAddress is required when docker=false"));
        }
        var options = new HoneypotService.DeploymentOptions(
            req.getName(),
            req.getType(),
            req.getIpAddress(),
            req.getPort(),
            req.isDocker(),
            req.getDockerImage(),
            req.getContainerPort()
        );
        return ResponseEntity.ok(honeypotService.deployHoneypot(options));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deactivate(@PathVariable Long id) {
        honeypotService.deactivateHoneypot(id);
        return ResponseEntity.ok(Map.of("message", "Honeypot deactivated"));
    }

    @GetMapping("/interactions")
    public ResponseEntity<?> getInteractions(
            @RequestParam(defaultValue = "0")  int page,
            @RequestParam(defaultValue = "50") int size) {
        return ResponseEntity.ok(honeypotService.getInteractions(page, size));
    }

    @PostMapping("/{id}/interactions")
    public ResponseEntity<?> recordInteraction(
            @PathVariable Long id,
            @RequestBody Map<String, String> body) {
        return ResponseEntity.ok(honeypotService.recordInteraction(
            id, body.get("attackerIp"), body.get("data")));
    }

    @GetMapping("/attackers")
    public ResponseEntity<?> getTopAttackers(
            @RequestParam(defaultValue = "20") int limit) {
        return ResponseEntity.ok(honeypotService.getTopAttackers(limit));
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        return ResponseEntity.ok(honeypotService.getHoneypotStats());
    }

    @Data
    public static class DeployRequest {
        @NotBlank String name;
        @NotBlank String type;      // ssh, http, ftp, smtp, telnet, rdp
        String ipAddress;
        @Min(1)
        int port = 2222;
        boolean docker = false;
        String dockerImage;
        Integer containerPort;
    }
}

