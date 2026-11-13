package com.kavachopsai.controller;

import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.JsonNode;
import com.kavachopsai.service.PythonMlGateway;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/ml")
@RequiredArgsConstructor
@PreAuthorize("isAuthenticated()")
public class MlController {

    private final PythonMlGateway mlGateway;

    @GetMapping("/health")
    public ResponseEntity<JsonNode> health() {
        return ResponseEntity.ok(mlGateway.getJson("/api/health"));
    }

    @PostMapping("/anomaly/detect")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
    public ResponseEntity<JsonNode> detectAnomaly(@RequestBody JsonNode payload) {
        return ResponseEntity.ok(mlGateway.postJson("/api/anomaly/detect", payload));
    }

    @PostMapping("/anomaly/batch")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
    public ResponseEntity<JsonNode> detectAnomalies(@RequestBody JsonNode payload) {
        return ResponseEntity.ok(mlGateway.postJson("/api/anomaly/batch", payload));
    }

    @PostMapping("/anomaly/train")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    public ResponseEntity<JsonNode> trainAnomalyModel(@RequestBody JsonNode payload) {
        return ResponseEntity.ok(mlGateway.postJson("/api/anomaly/train", payload));
    }

    @PostMapping("/malware/analyze")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
    public ResponseEntity<JsonNode> analyzeMalware(@RequestBody JsonNode payload) {
        return ResponseEntity.ok(mlGateway.postJson("/api/malware/analyze", payload));
    }

    @PostMapping(value = "/sarvam/report", produces = MediaType.APPLICATION_PDF_VALUE)
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
    public ResponseEntity<byte[]> generateSarvamReport(@RequestBody JsonNode payload) {
        byte[] pdf = mlGateway.postPdf("/api/sarvam/report", payload);
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_PDF)
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename("KavachOps_AI_Sarvam_Report.pdf").build().toString())
                .body(pdf);
    }
}
