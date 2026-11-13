package com.kavachopsai.controller;

import java.time.LocalDate;
import java.time.ZonedDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.kavachopsai.dto.CveRecordSummary;
import com.kavachopsai.dto.ReportChecklistItem;
import com.kavachopsai.model.Incident;
import com.kavachopsai.model.MalwareScan;
import com.kavachopsai.model.NetworkAlert;
import com.kavachopsai.model.WindowsEventLog;
import com.kavachopsai.repository.IncidentRepository;
import com.kavachopsai.repository.MalwareScanRepository;
import com.kavachopsai.repository.NetworkAlertsRepository;
import com.kavachopsai.repository.WindowsEventLogRepository;
import com.kavachopsai.service.VulnerabilityReportService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/reports")
@RequiredArgsConstructor
public class ReportController {

    private final VulnerabilityReportService reportService;
    private final NetworkAlertsRepository networkAlertsRepository;
    private final IncidentRepository incidentRepository;
    private final MalwareScanRepository malwareScanRepository;
    private final WindowsEventLogRepository windowsEventLogRepository;

    @GetMapping("/vulnerability/pdf")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
    public ResponseEntity<byte[]> downloadVulnerabilityPdf(
        @RequestParam(required = false) String severity,
        @RequestParam(required = false) String status,
        @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
        @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to
    ) {
        byte[] pdf = reportService.generateVulnerabilityPdf(severity, status, from, to);

        String filename = "vulnerability_report_" + LocalDate.now() + ".pdf";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_PDF);
        headers.setContentDisposition(ContentDisposition.attachment().filename(filename).build());

        return ResponseEntity.ok()
            .headers(headers)
            .body(pdf);
    }

        @GetMapping("/sync")
        @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
        public ResponseEntity<Map<String, Object>> syncReportData(
            @RequestParam(defaultValue = "30") int days,
            @RequestParam(defaultValue = "1000") int limit
        ) {
        int safeDays = Math.min(Math.max(days, 1), 365);
        int safeLimit = Math.min(Math.max(limit, 100), 5000);
        ZonedDateTime since = ZonedDateTime.now().minusDays(safeDays);
        Pageable pageable = PageRequest.of(0, safeLimit);

        List<NetworkAlert> alerts = networkAlertsRepository
            .findByTimestampAfterOrderByTimestampDesc(since, pageable)
            .getContent();
        List<Incident> incidents = incidentRepository
            .findByCreatedAtAfterOrderByCreatedAtDesc(since, pageable)
            .getContent();
        List<MalwareScan> malwareScans = malwareScanRepository
            .findByScanTimeAfterOrderByScanTimeDesc(since, pageable)
            .getContent();
        List<WindowsEventLog> windowsEvents = windowsEventLogRepository
            .findByEventTimeAfterOrderByEventTimeDesc(since, pageable)
            .getContent();
        List<CveRecordSummary> cveRecords = reportService.getTopCveRecords(since, 12);

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("alerts", networkAlertsRepository.countSince(since));
        summary.put("openIncidents", incidents.stream().filter(i -> {
            String s = i.getStatus() == null ? "" : i.getStatus().toLowerCase();
            return "open".equals(s) || "investigating".equals(s);
        }).count());
        summary.put("incidents", incidentRepository.countSince(since));
        summary.put("infectedFiles", malwareScanRepository.countInfectedSince(since));
        summary.put("malwareScans", malwareScanRepository.countScansSince(since));
        summary.put("windowsEvents", windowsEventLogRepository.countSince(since));
        summary.put("windowsSecurityEvents", windowsEventLogRepository.countSecurityEventsSince(since));

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("alerts", alerts);
        data.put("incidents", incidents);
        data.put("malwareScans", malwareScans);
        data.put("winEvents", windowsEvents);

        List<ReportChecklistItem> checks = reportService.buildReportChecklist(summary, safeDays, cveRecords);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("days", safeDays);
        payload.put("since", since);
        payload.put("limit", safeLimit);
        payload.put("summary", summary);
        payload.put("data", data);
        payload.put("cveRecords", cveRecords);
        payload.put("checks", checks);
        return ResponseEntity.ok(payload);
        }
}

