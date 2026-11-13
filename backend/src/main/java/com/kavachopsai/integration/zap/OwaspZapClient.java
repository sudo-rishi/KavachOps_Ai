package com.kavachopsai.integration.zap;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class OwaspZapClient {

    private final HttpClient httpClient;
    private final ObjectMapper mapper;
    private final String baseUrl;
    private final String apiKey;
    private final boolean enabled;
    private final Duration pollInterval;
    private final Duration timeout;

    public OwaspZapClient(
            @Value("${kavachopsai.zap.base-url:http://localhost:8090}") String baseUrl,
            @Value("${kavachopsai.zap.api-key:}") String apiKey,
            @Value("${kavachopsai.zap.enabled:false}") boolean enabled,
            @Value("${kavachopsai.zap.poll-interval-ms:2000}") long pollIntervalMs,
            @Value("${kavachopsai.zap.scan-timeout-seconds:900}") long timeoutSeconds) {
        this.baseUrl = sanitizeBaseUrl(baseUrl);
        this.apiKey = apiKey;
        this.enabled = enabled;
        this.pollInterval = Duration.ofMillis(Math.max(500L, pollIntervalMs));
        this.timeout = Duration.ofSeconds(Math.max(60L, timeoutSeconds));
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        this.mapper = new ObjectMapper().findAndRegisterModules();
    }

    public boolean isEnabled() {
        return enabled;
    }

    public ZapScanResult scanUrl(String targetUrl) throws Exception {
        if (!enabled) {
            throw new IllegalStateException("OWASP ZAP integration is disabled");
        }
        String encodedTarget = URLEncoder.encode(targetUrl, StandardCharsets.UTF_8);
        String scanId = startScan(encodedTarget);
        waitForCompletion(scanId);
        List<ZapAlert> alerts = fetchAlerts(encodedTarget);
        return new ZapScanResult(scanId, targetUrl, alerts);
    }

    private String startScan(String encodedTarget) throws Exception {
        JsonNode node = invokeJson("/JSON/ascan/action/scan/?url=" + encodedTarget + "&recurse=true");
        String scanId = node.path("scan").asText(null);
        if (scanId == null) {
            throw new IllegalStateException("OWASP ZAP did not return a scan id");
        }
        log.info("OWASP ZAP scan started: {}", scanId);
        return scanId;
    }

    private void waitForCompletion(String scanId) throws Exception {
        Instant deadline = Instant.now().plus(timeout);
        while (Instant.now().isBefore(deadline)) {
            JsonNode node = invokeJson("/JSON/ascan/view/status/?scanId=" + scanId);
            int status = node.path("status").asInt(0);
            if (status >= 100) {
                log.info("OWASP ZAP scan {} completed", scanId);
                return;
            }
            Thread.sleep(pollInterval.toMillis());
        }
        throw new IllegalStateException("OWASP ZAP scan timed out after " + timeout.toSeconds() + " seconds");
    }

    private List<ZapAlert> fetchAlerts(String encodedTarget) throws Exception {
        JsonNode node = invokeJson("/JSON/core/view/alerts/?baseurl=" + encodedTarget + "&start=0&count=9999");
        List<ZapAlert> alerts = new ArrayList<>();
        if (node.has("alerts")) {
            for (JsonNode alertNode : node.get("alerts")) {
                alerts.add(parseAlert(alertNode));
            }
        }
        return alerts;
    }

    private ZapAlert parseAlert(JsonNode node) {
        String risk = node.path("risk").asText("info");
        return new ZapAlert(
                node.path("alert").asText("Unknown"),
                risk,
                node.path("description").asText(""),
                node.path("solution").asText(""),
                node.path("reference").asText(""),
                node.path("url").asText(""),
                node.path("param").asText(""),
                node.path("attack").asText(""),
                node.path("evidence").asText(""),
                node.path("cweid").asText("")
        );
    }

    private JsonNode invokeJson(String pathAndQuery) throws Exception {
        String url = baseUrl + appendApiKey(pathAndQuery);
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .GET()
                .build();
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            throw new IllegalStateException("OWASP ZAP API call failed (" + resp.statusCode() + "): " + pathAndQuery);
        }
        return mapper.readTree(resp.body());
    }

    private String appendApiKey(String pathAndQuery) {
        if (apiKey == null || apiKey.isBlank()) {
            return pathAndQuery;
        }
        return pathAndQuery + (pathAndQuery.contains("?") ? "&" : "?")
                + "apikey=" + URLEncoder.encode(apiKey, StandardCharsets.UTF_8);
    }

    private String sanitizeBaseUrl(String raw) {
        if (raw == null || raw.isBlank()) {
            return "http://localhost:8090";
        }
        String trimmed = raw.trim();
        return trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
    }

    public record ZapAlert(
            String alertName,
            String risk,
            String description,
            String solution,
            String reference,
            String url,
            String parameter,
            String attack,
            String evidence,
            String cweId) {

        public String severity() {
            String normalized = risk == null ? "" : risk.toLowerCase(Locale.ROOT);
            return switch (normalized) {
                case "high" -> "critical";
                case "medium" -> "high";
                case "low" -> "medium";
                default -> "low";
            };
        }
    }

    @Getter
    public static class ZapScanResult {
        private final String scanId;
        private final String targetUrl;
        private final List<ZapAlert> alerts;

        public ZapScanResult(String scanId, String targetUrl, List<ZapAlert> alerts) {
            this.scanId = scanId;
            this.targetUrl = targetUrl;
            this.alerts = alerts == null ? List.of() : List.copyOf(alerts);
        }

        public boolean hasAlerts() {
            return !alerts.isEmpty();
        }
    }
}

