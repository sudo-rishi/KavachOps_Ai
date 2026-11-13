package com.kavachopsai.integration.cowrie;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kavachopsai.config.CowrieIntegrationProperties;
import com.kavachopsai.model.Honeypot;
import com.kavachopsai.repository.HoneypotRepository;
import com.kavachopsai.service.HoneypotService;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Polls Cowrie's JSON log (var/log/cowrie/cowrie.json) and turns interesting
 * events into persisted honeypot interactions inside KavachOps Ai.
 */
@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "kavachopsai.honeypot.cowrie", name = "enabled", havingValue = "true")
public class CowrieLogIngestor {

    private static final Set<String> INTERESTING_EVENTS = Set.of(
        "cowrie.session.connect",
        "cowrie.session.input",
        "cowrie.session.file_download",
        "cowrie.session.file_upload",
        "cowrie.command.failed",
        "cowrie.login.success",
        "cowrie.login.failed"
    );

    private final CowrieIntegrationProperties props;
    private final HoneypotRepository honeypotRepository;
    private final HoneypotService honeypotService;
    private final ObjectMapper objectMapper;

    private final AtomicLong lastOffset = new AtomicLong(0L);
    private Path logPath;
    private Long honeypotId;

    @PostConstruct
    void init() {
        if (props.getLogPath() == null || props.getLogPath().isBlank()) {
            log.warn("Cowrie ingestion enabled but kavachopsai.honeypot.cowrie.log-path is not set.");
            return;
        }
        logPath = Paths.get(props.getLogPath().trim()).toAbsolutePath().normalize();
        try {
            if (props.isTailFromEnd() && Files.exists(logPath)) {
                lastOffset.set(Files.size(logPath));
            }
        } catch (IOException e) {
            log.warn("Unable to determine initial Cowrie log size: {}", e.getMessage());
        }
        ensureHoneypotRecord();
    }

    @Scheduled(fixedDelayString = "${kavachopsai.honeypot.cowrie.poll-interval-ms:4000}")
    public void pollCowrieLog() {
        if (logPath == null || honeypotId == null) {
            return;
        }
        if (!Files.exists(logPath)) {
            log.debug("Cowrie log not found yet at {}", logPath);
            return;
        }
        try (RandomAccessFile raf = new RandomAccessFile(logPath.toFile(), "r")) {
            long fileLength = raf.length();
            long pointer = lastOffset.get();
            if (pointer > fileLength) {
                pointer = fileLength;
            }
            raf.seek(pointer);
            String raw;
            while ((raw = raf.readLine()) != null) {
                pointer = raf.getFilePointer();
                String line = new String(raw.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8).trim();
                if (!line.isEmpty()) {
                    processLine(line);
                }
            }
            lastOffset.set(pointer);
        } catch (IOException e) {
            log.error("Failed to read Cowrie log: {}", e.getMessage());
        }
    }

    private void ensureHoneypotRecord() {
        Honeypot honeypot = honeypotRepository.findByHoneypotName(props.getHoneypotName())
            .orElseGet(() -> honeypotRepository.save(Honeypot.builder()
                .honeypotName(props.getHoneypotName())
                .honeypotType(props.getHoneypotType())
                .ipAddress(props.getHostIp())
                .port(props.getHostPort())
                .deploymentType("external")
                .dockerImage("cowrie/cowrie:latest")
                .lastKnownState("external")
                .active(true)
                .build()));
        this.honeypotId = honeypot.getHoneypotId();
    }

    private void processLine(String jsonLine) {
        try {
            CowrieEvent event = objectMapper.readValue(jsonLine, CowrieEvent.class);
            if (event.eventid == null || !INTERESTING_EVENTS.contains(event.eventid)) {
                return;
            }
            String attackerIp = firstNonBlank(event.srcIp, event.peerIp);
            if (attackerIp == null) {
                return;
            }
            String data = buildSummary(event);
            honeypotService.recordInteraction(honeypotId, attackerIp, data);
        } catch (Exception e) {
            log.debug("Skipping Cowrie line ({}): {}", e.getClass().getSimpleName(), e.getMessage());
        }
    }

    private static String buildSummary(CowrieEvent event) {
        StringBuilder sb = new StringBuilder(event.eventid);
        if (event.input != null && !event.input.isBlank()) {
            sb.append(" :: ").append(event.input.trim());
        } else if (event.message != null && !event.message.isBlank()) {
            sb.append(" :: ").append(event.message.trim());
        }
        if (event.filename != null) {
            sb.append(" | file=").append(event.filename);
        }
        if (event.url != null) {
            sb.append(" | url=").append(event.url);
        }
        if (event.outfile != null) {
            sb.append(" | saved=").append(event.outfile);
        }
        if (event.username != null || event.password != null) {
            sb.append(" | creds=")
              .append(event.username != null ? event.username : "?")
              .append('/')
              .append(event.password != null ? event.password : "?");
        }
        if (event.session != null) {
            sb.append(" | session=").append(event.session);
        }
        String summary = sb.toString();
        return summary.length() > 1900 ? summary.substring(0, 1900) : summary;
    }

    private static String firstNonBlank(String... values) {
        for (String v : values) {
            if (v != null) {
                String trimmed = v.trim();
                if (!trimmed.isEmpty()) {
                    return trimmed;
                }
            }
        }
        return null;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class CowrieEvent {
        @JsonProperty("eventid")
        private String eventid;
        @JsonProperty("message")
        private String message;
        @JsonProperty("src_ip")
        private String srcIp;
        @JsonProperty("peer_ip")
        private String peerIp;
        @JsonProperty("input")
        private String input;
        @JsonProperty("outfile")
        private String outfile;
        @JsonProperty("filename")
        private String filename;
        @JsonProperty("url")
        private String url;
        @JsonProperty("username")
        private String username;
        @JsonProperty("password")
        private String password;
        @JsonProperty("session")
        private String session;
    }
}

