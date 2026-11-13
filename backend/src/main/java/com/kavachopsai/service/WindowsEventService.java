package com.kavachopsai.service;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.kavachopsai.model.NetworkAlert;
import com.kavachopsai.model.WindowsEventLog;
import com.kavachopsai.repository.NetworkAlertsRepository;
import com.kavachopsai.repository.WindowsEventLogRepository;
import com.kavachopsai.websocket.AlertBroadcaster;
import com.kavachopsai.windows.WindowsEventCatalog;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class WindowsEventService {

    private final WindowsEventLogRepository eventRepo;
    private final NetworkAlertsRepository alertRepo;
    private final AlertBroadcaster broadcaster;
    private final IncidentService incidentService;
    private final WindowsEventCatalog windowsEventCatalog;
    private final AtomicLong eventsIngested = new AtomicLong(0);
    private final AtomicLong alertsGenerated = new AtomicLong(0);

    // High-value event IDs that should always generate alerts
    private static final Map<Long, String> ALERT_EVENT_IDS = Map.ofEntries(
        Map.entry(4625L, "FAILED_LOGON"),
        Map.entry(4648L, "EXPLICIT_CREDENTIAL_LOGON"),
        Map.entry(4672L, "SPECIAL_PRIVILEGES_ASSIGNED"),
        Map.entry(4698L, "SCHEDULED_TASK_CREATED"),
        Map.entry(4699L, "SCHEDULED_TASK_DELETED"),
        Map.entry(4719L, "AUDIT_POLICY_CHANGED"),
        Map.entry(4720L, "USER_ACCOUNT_CREATED"),
        Map.entry(4726L, "USER_ACCOUNT_DELETED"),
        Map.entry(4728L, "GROUP_MEMBER_ADDED"),
        Map.entry(4732L, "LOCAL_GROUP_MEMBER_ADDED"),
        Map.entry(4740L, "ACCOUNT_LOCKED_OUT"),
        Map.entry(7045L, "NEW_SERVICE_INSTALLED"),
        Map.entry(4688L, "PROCESS_CREATED")
    );

    // Event IDs that are CRITICAL severity
    private static final Set<Long> CRITICAL_EVENT_IDS = Set.of(
        4719L, 4720L, 4726L, 4740L, 7045L, 4698L
    );

    @Transactional
    public void ingestEvents(List<WindowsEventLog> events) {
        if (events == null || events.isEmpty()) {
            return;
        }
        List<WindowsEventLog> savedEvents = eventRepo.saveAll(events);
        eventsIngested.addAndGet(savedEvents.size());
        List<NetworkAlert> alertsToCreate = new ArrayList<>();

        for (WindowsEventLog event : savedEvents) {
            // Broadcast to frontend
            broadcaster.broadcastWindowsEvent(event);

            // Check if this event should trigger an alert
            if (ALERT_EVENT_IDS.containsKey(event.getEventId())) {
                NetworkAlert alert = buildAlertFromEvent(event);
                alertsToCreate.add(alert);
                event.setAlertGenerated(true);
            }
        }

        if (!alertsToCreate.isEmpty()) {
            List<NetworkAlert> savedAlerts = alertRepo.saveAll(alertsToCreate);
            alertsGenerated.addAndGet(savedAlerts.size());
            for (NetworkAlert alert : savedAlerts) {
                broadcaster.broadcastAlert(alert);
                if ("CRITICAL".equals(alert.getSeverity())) {
                    incidentService.autoCreateFromAlert(alert);
                }
            }
            log.info("Generated {} alerts from {} Windows events", savedAlerts.size(), events.size());
        }
    }

    private NetworkAlert buildAlertFromEvent(WindowsEventLog event) {
        String severity = CRITICAL_EVENT_IDS.contains(event.getEventId()) ? "CRITICAL"
                        : isMediumEvent(event.getEventId()) ? "MEDIUM" : "HIGH";

        String alertType = ALERT_EVENT_IDS.get(event.getEventId());
        String message = String.format("[WinEvent %d] %s on %s: %s",
                event.getEventId(),
                alertType,
                orEmpty(event.getComputerName()),
                truncate(orEmpty(event.getMessage()), 400)
        );

        return NetworkAlert.builder()
                .sourceIp("127.0.0.1") // Windows local events
                .destinationIp("127.0.0.1")
                .severity(severity)
                .timestamp(event.getEventTime())
                .status("new")
                .alertType("WINDOWS_EVENT")
                .alertMessage(message)
                .packetData("EventID=" + event.getEventId() + " Channel=" + event.getChannel())
                .build();
    }

    private boolean isMediumEvent(long eventId) {
        return Set.of(4624L, 4634L, 4688L, 4728L, 4732L).contains(eventId);
    }

    // â”€â”€â”€ Query Methods â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    @Transactional(readOnly = true)
    public Page<WindowsEventLog> getEvents(String channel, String level, int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("eventTime").descending());
        if (channel != null && !channel.isBlank()) {
            return eventRepo.findByChannelOrderByEventTimeDesc(channel, pageable);
        }
        if (level != null && !level.isBlank()) {
            return eventRepo.findByLevelOrderByEventTimeDesc(level, pageable);
        }
        return eventRepo.findAll(pageable);
    }

    @Transactional(readOnly = true)
    public Map<String, Object> getEventStats() {
        ZonedDateTime last24h = ZonedDateTime.now().minusHours(24);
        ZonedDateTime last1h  = ZonedDateTime.now().minusHours(1);

        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("totalEvents24h",        eventRepo.countSince(last24h));
        stats.put("securityEvents24h",     eventRepo.countSecurityEventsSince(last24h));
        stats.put("securityEvents1h",      eventRepo.countSecurityEventsSince(last1h));

        // Top event IDs
        List<Object[]> topIds = eventRepo.topEventIds(last24h, PageRequest.of(0, 10));
        List<Map<String, Object>> topIdsList = new ArrayList<>();
        for (Object[] row : topIds) {
            Long id = (Long) row[0];
            String catalogName = windowsEventCatalog.find(id)
                    .map(WindowsEventCatalog.EventMeta::description)
                    .orElse(null);
            topIdsList.add(Map.of(
                "eventId", id,
                "count",   row[1],
                "name",    catalogName != null ? catalogName : ALERT_EVENT_IDS.getOrDefault(id, "OTHER")
            ));
        }
        stats.put("topEventIds", topIdsList);
        stats.put("eventsIngestedRuntime", eventsIngested.get());
        stats.put("alertsGeneratedRuntime", alertsGenerated.get());

        return stats;
    }

    @Transactional(readOnly = true)
    public List<WindowsEventLog> getRecentSecurityEvents(int limit) {
        return eventRepo.findBySecurityRelevantTrueOrderByEventTimeDesc(
                PageRequest.of(0, limit));
    }

    @Transactional(readOnly = true)
    public Map<String, Object> getEventCatalogEntry(long eventId) {
        return windowsEventCatalog.find(eventId)
                .map(meta -> {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("eventId", meta.eventId());
                    out.put("source", meta.sourceName());
                    out.put("description", meta.description());
                    out.put("category", meta.category());
                    out.put("known", true);
                    return out;
                })
                .orElseGet(() -> {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("eventId", eventId);
                    out.put("known", false);
                    out.put("description", "Unknown event ID in local catalog");
                    return out;
                });
    }

    @Transactional(readOnly = true)
    public Map<String, Object> getCatalogStatus() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("entries", windowsEventCatalog.size());
        out.put("loaded", windowsEventCatalog.size() > 0);
        return out;
    }

    private String orEmpty(String s)      { return s != null ? s : ""; }
    private String truncate(String s, int n) { return s.length() > n ? s.substring(0, n) + "..." : s; }
}

