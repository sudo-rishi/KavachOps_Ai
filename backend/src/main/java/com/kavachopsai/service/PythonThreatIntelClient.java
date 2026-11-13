package com.kavachopsai.service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class PythonThreatIntelClient {

    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();
    private HttpClient httpClient;

    @Value("${python.malware.enabled:false}")
    private boolean malwareEnabled;

    @Value("${python.malware.base-url:http://localhost:5001}")
    private String malwareBaseUrl;

    @Value("${python.yara.enabled:false}")
    private boolean yaraEnabled;

    @Value("${python.yara.base-url:http://localhost:5002}")
    private String yaraBaseUrl;

    @Value("${python.yara.rules-dir:}")
    private String yaraRulesDir;

    @Value("${python.request.connect-timeout-ms:1500}")
    private int connectTimeoutMs;

    @Value("${python.request.read-timeout-ms:2500}")
    private int readTimeoutMs;

    @PostConstruct
    void initHttpClient() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(connectTimeoutMs))
                .build();
    }

    public Optional<PythonMlResult> scanFileWithMl(String filePath) {
        if (!malwareEnabled) {
            return Optional.empty();
        }
        try {
            String body = mapper.writeValueAsString(Map.of("filePath", filePath));
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(trimTrailingSlash(malwareBaseUrl) + "/api/scan-file"))
                    .timeout(Duration.ofMillis(readTimeoutMs))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() >= 300) {
                log.debug("ML API non-success status {}", response.statusCode());
                return Optional.empty();
            }

            JsonNode root = mapper.readTree(response.body());
            String label = root.path("label").asText("");
            double confidence = root.path("confidence").asDouble(0.0);
            int classId = root.path("class_id").asInt(-1);
            return Optional.of(new PythonMlResult(label, confidence, classId));
        } catch (Exception ex) {
            log.debug("ML API call failed: {}", ex.getMessage());
            return Optional.empty();
        }
    }

    public Optional<PythonYaraResult> scanFileWithYara(String filePath) {
        if (!yaraEnabled) {
            return Optional.empty();
        }
        try {
            Map<String, String> payload = yaraRulesDir == null || yaraRulesDir.isBlank()
                    ? Map.of("filePath", filePath)
                    : Map.of("filePath", filePath, "rulesDir", yaraRulesDir);

            String body = mapper.writeValueAsString(payload);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(trimTrailingSlash(yaraBaseUrl) + "/api/yara/scan-file"))
                    .timeout(Duration.ofMillis(readTimeoutMs))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() >= 300) {
                log.debug("YARA API non-success status {}", response.statusCode());
                return Optional.empty();
            }

            JsonNode root = mapper.readTree(response.body());
            List<String> matchedRules = new ArrayList<>();
            JsonNode matchedNode = root.path("matchedRules");
            if (matchedNode.isArray()) {
                for (JsonNode node : matchedNode) {
                    matchedRules.add(node.asText());
                }
            }
            boolean matched = root.path("matched").asBoolean(!matchedRules.isEmpty());
            int matchCount = root.path("matchCount").asInt(matchedRules.size());
            return Optional.of(new PythonYaraResult(matched, matchCount, matchedRules));
        } catch (Exception ex) {
            log.debug("YARA API call failed: {}", ex.getMessage());
            return Optional.empty();
        }
    }

    private String trimTrailingSlash(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    public record PythonMlResult(String label, double confidence, int classId) {
        public boolean malwareHighConfidence(double thresholdPercent) {
            String lowered = label == null ? "" : label.toLowerCase();
            boolean malwareLike = classId == 1 || lowered.contains("malware") || lowered.contains("suspicious") || lowered.contains("trojan") || lowered.contains("ransom");
            return malwareLike && confidence >= thresholdPercent;
        }
    }

    public record PythonYaraResult(boolean matched, int matchCount, List<String> matchedRules) {
    }
}

