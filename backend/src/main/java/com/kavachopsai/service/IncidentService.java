package com.kavachopsai.service;

import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.kavachopsai.model.Incident;
import com.kavachopsai.model.IncidentTimeline;
import com.kavachopsai.model.NetworkAlert;
import com.kavachopsai.model.User;
import com.kavachopsai.repository.IncidentRepository;
import com.kavachopsai.repository.IncidentTimelineRepository;
import com.kavachopsai.repository.UserRepository;
import com.kavachopsai.websocket.AlertBroadcaster;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class IncidentService {

    private static final Set<String> VALID_STATUSES = new HashSet<>(Arrays.asList(
        "open", "investigating", "contained", "resolved", "closed"
    ));
    private static final Set<String> VALID_SEVERITIES = new HashSet<>(Arrays.asList(
        "critical", "high", "medium", "low"
    ));

    private final IncidentRepository incidentRepo;
    private final IncidentTimelineRepository timelineRepo;
    private final UserRepository userRepo;
    private final AlertBroadcaster broadcaster;

    private final AtomicLong incidentCounter = new AtomicLong(0);

    // â”€â”€â”€ Auto-creation from alerts â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    @Transactional
    public void autoCreateFromAlert(NetworkAlert alert) {
        try {
            Incident incident = Incident.builder()
                    .incidentNumber(generateIncidentNumber())
                    .title(String.format("Auto: %s from %s",
                            orEmpty(alert.getAlertType()),
                            alert.getSourceIp()))
                    .description(orEmpty(alert.getAlertMessage()))
                    .severity(mapAlertSeverity(alert.getSeverity()))
                    .status("open")
                    .sourceAlertId(alert.getAlertId())
                    .affectedAssets(alert.getDestinationIp())
                    .build();

            Incident saved = incidentRepo.save(incident);

            // Add initial timeline entry
            IncidentTimeline entry = IncidentTimeline.builder()
                    .incident(saved)
                    .actionType("created")
                    .description("Incident auto-created from " + orEmpty(alert.getAlertType())
                            + " alert. Source: " + alert.getSourceIp())
                    .build();
            timelineRepo.save(entry);

            broadcaster.broadcastIncident(saved);
            log.info("Auto-created incident {} from {} alert", saved.getIncidentNumber(), alert.getAlertType());

        } catch (Exception e) {
            log.error("Failed to auto-create incident: {}", e.getMessage());
        }
    }

    // â”€â”€â”€ Manual CRUD â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    @Transactional
    public Incident createIncident(String title, String description, String severity,
                                   String createdByUsername, String affectedAssets) {
        User creator = userRepo.findByUsername(createdByUsername).orElse(null);

        String normalizedSeverity = normalizeSeverityForCreate(severity);

        Incident incident = Incident.builder()
                .incidentNumber(generateIncidentNumber())
                .title(title)
            .description(description)
            .severity(normalizedSeverity)
                .status("open")
                .createdBy(creator)
                .affectedAssets(affectedAssets)
                .build();

        Incident saved = incidentRepo.save(incident);

        IncidentTimeline entry = IncidentTimeline.builder()
                .incident(saved)
                .actionType("created")
                .description("Incident manually created by " + createdByUsername)
                .performedBy(creator)
                .build();
        timelineRepo.save(entry);

        broadcaster.broadcastIncident(saved);
        return saved;
    }

    @Transactional
    public Incident updateStatus(Long incidentId, String newStatus, String updatedByUsername) {
        Incident incident = incidentRepo.findById(incidentId)
                .orElseThrow(() -> new NoSuchElementException("Incident not found: " + incidentId));

        String normalizedStatus = normalizeStatus(newStatus);
        if (!VALID_STATUSES.contains(normalizedStatus)) {
            throw new IllegalArgumentException("Invalid incident status: " + newStatus);
        }

        String oldStatus = incident.getStatus();
        incident.setStatus(normalizedStatus);

        if ("resolved".equals(normalizedStatus) || "closed".equals(normalizedStatus)) {
            incident.setResolvedAt(ZonedDateTime.now());
        }

        Incident saved = incidentRepo.save(incident);

        User updater = userRepo.findByUsername(updatedByUsername).orElse(null);
        IncidentTimeline entry = IncidentTimeline.builder()
                .incident(saved)
                .actionType("updated")
                .description(String.format("Status changed from '%s' to '%s' by %s",
                    oldStatus, normalizedStatus, updatedByUsername))
                .performedBy(updater)
                .build();
        timelineRepo.save(entry);

        broadcaster.broadcastIncident(saved);
        return saved;
    }

    @Transactional
    public IncidentTimeline addNote(Long incidentId, String note, String authorUsername) {
        Incident incident = incidentRepo.findById(incidentId)
                .orElseThrow(() -> new NoSuchElementException("Incident not found: " + incidentId));
        if (note == null || note.isBlank()) {
            throw new IllegalArgumentException("Incident note cannot be empty");
        }
        User author = userRepo.findByUsername(authorUsername).orElse(null);

        IncidentTimeline entry = IncidentTimeline.builder()
                .incident(incident)
                .actionType("note")
                .description(note)
                .performedBy(author)
                .build();

        return timelineRepo.save(entry);
    }

    // â”€â”€â”€ Query methods â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    @Transactional(readOnly = true)
    public Page<Incident> getIncidents(String status, String severity, int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        String normalizedStatus = normalizeStatus(status);
        String normalizedSeverity = normalizeSeverityFilter(severity);

        if (!normalizedStatus.isBlank() && !normalizedSeverity.isBlank()) {
            return incidentRepo.findByStatusAndSeverityOrderByCreatedAtDesc(normalizedStatus, normalizedSeverity, pageable);
        }
        if (!normalizedStatus.isBlank()) {
            return incidentRepo.findByStatusOrderByCreatedAtDesc(normalizedStatus, pageable);
        }
        if (!normalizedSeverity.isBlank()) {
            return incidentRepo.findBySeverityOrderByCreatedAtDesc(normalizedSeverity, pageable);
        }
        return incidentRepo.findAll(pageable);
    }

    @Transactional(readOnly = true)
    public Optional<Incident> getById(Long id) {
        return incidentRepo.findById(id);
    }

    @Transactional(readOnly = true)
    public List<IncidentTimeline> getTimeline(Long incidentId) {
        return timelineRepo.findByIncident_IncidentIdOrderByTimestampAsc(incidentId);
    }

    @Transactional(readOnly = true)
    public Map<String, Object> getIncidentStats() {
        ZonedDateTime last24h = ZonedDateTime.now().minusHours(24);
        ZonedDateTime last7d  = ZonedDateTime.now().minusDays(7);

        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("openIncidents",     incidentRepo.countOpenIncidents());
        stats.put("newLast24h",        incidentRepo.countSince(last24h));
        stats.put("newLast7d",         incidentRepo.countSince(last7d));

        List<Object[]> sevRows = incidentRepo.severityStats(last7d);
        Map<String, Long> sevMap = new LinkedHashMap<>();
        for (Object[] row : sevRows) sevMap.put((String) row[0], (Long) row[1]);
        stats.put("bySeverity", sevMap);

        return stats;
    }

    // â”€â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    private String generateIncidentNumber() {
        String day = LocalDate.now().format(DateTimeFormatter.BASIC_ISO_DATE);
        String time = LocalTime.now().format(DateTimeFormatter.ofPattern("HHmmssSSS"));
        long seq = incidentCounter.incrementAndGet() % 1000;
        int rand = ThreadLocalRandom.current().nextInt(0x1000, 0x10000);
        return String.format("INC-%s-%s-%03d-%04X", day, time, seq, rand);
    }

    private String mapAlertSeverity(String alertSev) {
        return switch (alertSev.toUpperCase()) {
            case "CRITICAL" -> "critical";
            case "HIGH"     -> "high";
            case "MEDIUM"   -> "medium";
            default         -> "low";
        };
    }

    private String normalizeStatus(String status) {
        return status == null ? "" : status.trim().toLowerCase();
    }

    private String normalizeSeverityFilter(String severity) {
        if (severity == null || severity.isBlank()) {
            return "";
        }
        String normalized = severity.trim().toLowerCase();
        return VALID_SEVERITIES.contains(normalized) ? normalized : "";
    }

    private String normalizeSeverityForCreate(String severity) {
        String normalized = normalizeSeverityFilter(severity);
        return normalized.isBlank() ? "medium" : normalized;
    }

    private String orEmpty(String s) { return s != null ? s : ""; }
}

