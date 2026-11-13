package com.kavachopsai.controller;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.kavachopsai.model.WindowsEventLog;
import com.kavachopsai.service.IncidentService;
import com.kavachopsai.service.MalwareDetectionService;
import com.kavachopsai.service.SarvamWindowsEventService;
import com.kavachopsai.service.WindowsEventService;
import com.kavachopsai.windows.WindowsEventLogReader;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  Incident Management Controller
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
@RestController
@RequestMapping("/incidents")
@RequiredArgsConstructor
class IncidentController {

    private final IncidentService incidentService;

    @GetMapping
    public ResponseEntity<?> getIncidents(
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String severity,
            @RequestParam(defaultValue = "0")  int page,
            @RequestParam(defaultValue = "20") int size) {
        return ResponseEntity.ok(incidentService.getIncidents(status, severity, page, size));
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getById(@PathVariable Long id) {
        return incidentService.getById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/{id}/timeline")
    public ResponseEntity<?> getTimeline(@PathVariable Long id) {
        return ResponseEntity.ok(incidentService.getTimeline(id));
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
    public ResponseEntity<?> createIncident(
            @Valid @RequestBody CreateIncidentRequest req,
            @AuthenticationPrincipal UserDetails user) {
        try {
            return ResponseEntity.ok(incidentService.createIncident(
                    req.getTitle(), req.getDescription(),
                    req.getSeverity(), user.getUsername(), req.getAffectedAssets()));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(Map.of("error", ex.getMessage()));
        }
    }

    @PatchMapping("/{id}/status")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
    public ResponseEntity<?> updateStatus(
            @PathVariable Long id,
            @RequestBody Map<String, String> body,
            @AuthenticationPrincipal UserDetails user) {
        try {
            return ResponseEntity.ok(
                    incidentService.updateStatus(id, body.get("status"), user.getUsername()));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(Map.of("error", ex.getMessage()));
        }
    }

    @PostMapping("/{id}/notes")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
    public ResponseEntity<?> addNote(
            @PathVariable Long id,
            @RequestBody Map<String, String> body,
            @AuthenticationPrincipal UserDetails user) {
        try {
            return ResponseEntity.ok(
                    incidentService.addNote(id, body.get("note"), user.getUsername()));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(Map.of("error", ex.getMessage()));
        }
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        return ResponseEntity.ok(incidentService.getIncidentStats());
    }

    @Data static class CreateIncidentRequest {
        @NotBlank String title;
        String description;
        @NotBlank String severity;
        String affectedAssets;
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  Windows Event Log Controller
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
@RestController
@RequestMapping("/events")
@RequiredArgsConstructor
class WindowsEventController {

    private final WindowsEventService windowsEventService;
    private final WindowsEventLogReader eventReader;
    private final SarvamWindowsEventService sarvamWindowsEventService;

    @GetMapping
    public ResponseEntity<?> getEvents(
            @RequestParam(required = false) String channel,
            @RequestParam(required = false) String level,
            @RequestParam(defaultValue = "0")  int page,
            @RequestParam(defaultValue = "50") int size) {
        return ResponseEntity.ok(windowsEventService.getEvents(channel, level, page, size));
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        return ResponseEntity.ok(windowsEventService.getEventStats());
    }

    @GetMapping("/security")
    public ResponseEntity<?> getSecurityEvents(
            @RequestParam(defaultValue = "50") int limit) {
        return ResponseEntity.ok(windowsEventService.getRecentSecurityEvents(limit));
    }

    @PostMapping("/sarvam/analyze")
    public ResponseEntity<?> analyzeWithSarvam(@RequestBody(required = false) Map<String, Object> body) {
        Map<String, Object> request = body == null ? Map.of() : body;
        Object questionValue = request.get("question");
        if (questionValue != null
                && (!(questionValue instanceof String) || ((String) questionValue).length() > 500)) {
            return ResponseEntity.badRequest().body(Map.of("error", "question must be at most 500 characters"));
        }
        String question = questionValue == null ? "" : ((String) questionValue).trim();

        String scope = String.valueOf(request.getOrDefault("scope", "security")).trim().toLowerCase();
        if (!scope.equals("security") && !scope.equals("all")) {
            return ResponseEntity.badRequest().body(Map.of("error", "scope must be 'security' or 'all'"));
        }

        int limit = 50;
        Object limitValue = request.get("limit");
        if (limitValue != null) {
            if (!(limitValue instanceof Number)) {
                return ResponseEntity.badRequest().body(Map.of("error", "limit must be an integer from 1 to 50"));
            }
            double value = ((Number) limitValue).doubleValue();
            if (!Double.isFinite(value) || value != Math.rint(value) || value < 1 || value > 50) {
                return ResponseEntity.badRequest().body(Map.of("error", "limit must be an integer from 1 to 50"));
            }
            limit = (int) value;
        }

        List<WindowsEventLog> events = scope.equals("security")
                ? windowsEventService.getRecentSecurityEvents(limit)
                : windowsEventService.getEvents(null, null, 0, limit).getContent();
        return ResponseEntity.ok(sarvamWindowsEventService.analyze(events, question, scope));
    }

    @GetMapping("/reader/status")
    public ResponseEntity<Map<String, Object>> readerStatus() {
        return ResponseEntity.ok(eventReader.getStatus());
    }

    @GetMapping("/catalog/status")
    public ResponseEntity<Map<String, Object>> catalogStatus() {
        return ResponseEntity.ok(windowsEventService.getCatalogStatus());
    }

    @GetMapping("/catalog/{eventId}")
    public ResponseEntity<Map<String, Object>> catalogEntry(@PathVariable Long eventId) {
        return ResponseEntity.ok(windowsEventService.getEventCatalogEntry(eventId));
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  Malware Detection Controller
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
@RestController
@RequestMapping("/malware")
@RequiredArgsConstructor

class MalwareController {

    private final MalwareDetectionService malwareService;

    @PostMapping("/scan")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
    public ResponseEntity<?> scanFile(@RequestBody Map<String, String> body) {
        String filePath = body.get("filePath");
        if (filePath == null || filePath.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "filePath is required"));
        }
        try {
            return ResponseEntity.ok(malwareService.scanFile(filePath));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(Map.of("error", ex.getMessage()));
        } catch (Exception ex) {
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", "Failed to scan file", "details", ex.getMessage()));
        }
    }

    @PostMapping("/upload")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
    public ResponseEntity<?> uploadAndScan(@RequestParam("file") MultipartFile file) {
        if (file == null || file.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "File is required"));
        }
        
        // Validate file size (max 500MB)
        final long MAX_FILE_SIZE = 500L * 1024L * 1024L;
        if (file.getSize() > MAX_FILE_SIZE) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "File size exceeds maximum limit of 500MB"));
        }
        
        Path tempDir = null;
        Path tempFile = null;
        try {
            // Create temporary directory for uploads
            tempDir = Files.createTempDirectory("malware-scan-");
            tempFile = tempDir.resolve(sanitizeFilename(file.getOriginalFilename()));
            
            // Save uploaded file to temp location
            file.transferTo(tempFile.toFile());
            
            // Scan the file
            return ResponseEntity.ok(malwareService.scanFile(tempFile.toAbsolutePath().toString()));
            
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(Map.of("error", ex.getMessage()));
        } catch (IOException ex) {
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", "Failed to process uploaded file", "details", ex.getMessage()));
        } catch (Exception ex) {
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", "Failed to scan file", "details", ex.getMessage()));
        } finally {
            // Clean up temporary files
            if (tempFile != null && Files.exists(tempFile)) {
                try {
                    Files.delete(tempFile);
                } catch (IOException e) {
                    // Log but don't fail - cleanup is best-effort
                }
            }
            if (tempDir != null && Files.exists(tempDir)) {
                try {
                    Files.delete(tempDir);
                } catch (IOException e) {
                    // Log but don't fail - cleanup is best-effort
                }
            }
        }
    }

    private static String sanitizeFilename(String originalName) {
        String fallback = "upload.bin";
        if (originalName == null || originalName.isBlank()) {
            return fallback;
        }

        String normalized = originalName.replace('\\', '/');
        int lastSlash = normalized.lastIndexOf('/');
        if (lastSlash >= 0 && lastSlash < normalized.length() - 1) {
            normalized = normalized.substring(lastSlash + 1);
        }

        normalized = normalized.replaceAll("[^A-Za-z0-9._-]", "_");
        if (normalized.isBlank()) {
            return fallback;
        }
        return normalized;
    }

    @GetMapping("/scans")
    public ResponseEntity<?> getScans(
            @RequestParam(required = false) String result,
            @RequestParam(defaultValue = "0")  int page,
            @RequestParam(defaultValue = "50") int size) {
        return ResponseEntity.ok(malwareService.getScans(result, page, size));
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        Map<String, Object> payload = new LinkedHashMap<>(malwareService.getMalwareStats());
        payload.put("filesystem", malwareService.getFileSystemRuntimeStats());
        return ResponseEntity.ok(payload);
    }

    @PostMapping("/scan/full")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    public ResponseEntity<?> startFullFilesystemScan(@RequestBody(required = false) Map<String, String> body) {
        String rootPath = body == null ? null : body.get("rootPath");
        return ResponseEntity.ok(malwareService.startFullSystemScan(rootPath));
    }

    @GetMapping("/scan/full/{jobId}")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
    public ResponseEntity<?> getFullFilesystemScanStatus(@PathVariable String jobId) {
        return ResponseEntity.ok(malwareService.getFileSystemScanStatus(jobId));
    }

    @PostMapping("/scan/full/{jobId}/stop")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    public ResponseEntity<?> stopFullFilesystemScan(@PathVariable String jobId) {
        return ResponseEntity.ok(malwareService.stopFileSystemScan(jobId));
    }

    @GetMapping("/scan/full/jobs")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
    public ResponseEntity<?> listFilesystemScanJobs() {
        return ResponseEntity.ok(Map.of("summary", malwareService.getFileSystemRuntimeStats()));
    }
}

