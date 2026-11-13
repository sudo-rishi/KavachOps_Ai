package com.kavachopsai.service;

import com.kavachopsai.capture.IdsRuleEngine;
import com.kavachopsai.model.IdsRule;
import com.kavachopsai.model.NetworkAlert;
import com.kavachopsai.model.NetworkTraffic;
import com.kavachopsai.repository.IdsRuleRepository;
import com.kavachopsai.repository.NetworkAlertsRepository;
import com.kavachopsai.repository.NetworkTrafficRepository;
import com.kavachopsai.websocket.AlertBroadcaster;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.ZonedDateTime;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@Service
@RequiredArgsConstructor
public class NetworkAnalysisService {

    private final NetworkTrafficRepository trafficRepo;
    private final NetworkAlertsRepository alertRepo;
    private final IdsRuleRepository ruleRepo;
    private final IdsRuleEngine ruleEngine;
    private final AlertBroadcaster broadcaster;
    private final IncidentService incidentService;

    // Async queue to avoid blocking the capture thread
    private final BlockingQueue<NetworkTraffic> trafficQueue = new LinkedBlockingQueue<>(10_000);
    private final AtomicLong droppedPackets = new AtomicLong(0);
    private final AtomicLong processedPackets = new AtomicLong(0);
    private final AtomicLong generatedAlerts = new AtomicLong(0);

    /**
     * Called by PacketCaptureEngine for every captured packet.
     * Non-blocking: queues the packet for async processing.
     */
    public void processTraffic(NetworkTraffic traffic) {
        if (!trafficQueue.offer(traffic)) {
            droppedPackets.incrementAndGet();
        }
    }

    /**
     * Background processor: drains the queue and persists + analyzes traffic.
     */
    @Async
    @Transactional
    public void drainQueue() {
        List<NetworkTraffic> batch = new ArrayList<>(100);
        trafficQueue.drainTo(batch, 100);
        if (batch.isEmpty()) return;
        processedPackets.addAndGet(batch.size());

        // Persist traffic records
        List<NetworkTraffic> saved = trafficRepo.saveAll(batch);

        // IDS rule matching
        List<NetworkAlert> allAlerts = new ArrayList<>();
        for (NetworkTraffic t : saved) {
            List<NetworkAlert> alerts = ruleEngine.match(t);
            allAlerts.addAll(alerts);
            // Live broadcast every packet (throttled in frontend)
            broadcaster.broadcastTraffic(t);
        }

        // Persist and broadcast alerts
        if (!allAlerts.isEmpty()) {
            List<NetworkAlert> savedAlerts = alertRepo.saveAll(allAlerts);
            generatedAlerts.addAndGet(savedAlerts.size());
            savedAlerts.forEach(alert -> {
                broadcaster.broadcastAlert(alert);
                // Auto-create incident for CRITICAL alerts
                if ("CRITICAL".equals(alert.getSeverity())) {
                    incidentService.autoCreateFromAlert(alert);
                }
            });
            log.debug("IDS: {} alerts from batch of {} packets.", savedAlerts.size(), batch.size());
        }
    }

    // â”€â”€â”€ Query methods â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    @Transactional(readOnly = true)
    public Page<NetworkTraffic> getRecentTraffic(int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("timestamp").descending());
        return trafficRepo.findAll(pageable);
    }

    @Transactional(readOnly = true)
    public Page<NetworkAlert> getAlerts(String status, int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("timestamp").descending());
        if (status != null && !status.isBlank()) {
            return alertRepo.findByStatusOrderByTimestampDesc(status, pageable);
        }
        return alertRepo.findAll(pageable);
    }

    @Transactional(readOnly = true)
    public Map<String, Object> getAlertStats() {
        ZonedDateTime last24h = ZonedDateTime.now().minusHours(24);
        ZonedDateTime last1h  = ZonedDateTime.now().minusHours(1);

        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("totalAlerts24h",    alertRepo.countActiveSince(last24h));
        stats.put("criticalAlerts1h",  alertRepo.countBySeveritySince("CRITICAL", last1h));
        stats.put("highAlerts24h",     alertRepo.countBySeveritySince("HIGH", last24h));
        stats.put("packetCount24h",    trafficRepo.countSince(last24h));
        stats.put("droppedPackets",    droppedPackets.get());
        stats.put("queueSize",         trafficQueue.size());
        stats.put("processedPacketsRuntime", processedPackets.get());
        stats.put("generatedAlertsRuntime", generatedAlerts.get());

        // Severity breakdown
        List<Object[]> sevRows = alertRepo.severityStats(last24h);
        Map<String, Long> sevMap = new LinkedHashMap<>();
        for (Object[] row : sevRows) {
            sevMap.put((String) row[0], (Long) row[1]);
        }
        stats.put("bySeverity", sevMap);

        // Protocol stats
        List<Object[]> protoRows = trafficRepo.protocolStats(last24h);
        Map<String, Long> protoMap = new LinkedHashMap<>();
        for (Object[] row : protoRows) {
            protoMap.put((String) row[0], (Long) row[1]);
        }
        stats.put("byProtocol", protoMap);

        // Top source IPs
        List<Object[]> topIps = trafficRepo.topSourceIps(last24h, PageRequest.of(0, 10));
        List<Map<String, Object>> ipList = new ArrayList<>();
        for (Object[] row : topIps) {
            ipList.add(Map.of("ip", row[0], "count", row[1]));
        }
        stats.put("topSourceIps", ipList);

        return stats;
    }

    @Transactional
    public NetworkAlert updateAlertStatus(Long alertId, String status) {
        alertRepo.updateStatus(alertId, status);
        return alertRepo.findById(alertId).orElseThrow();
    }

    @Transactional(readOnly = true)
    public List<IdsRule> getAllRules() {
        return ruleRepo.findAll();
    }

    @Transactional
    public IdsRule createRule(IdsRule rule) {
        IdsRule saved = ruleRepo.save(rule);
        ruleEngine.reloadRules();
        return saved;
    }

    @Transactional
    public void deleteRule(Long ruleId) {
        ruleRepo.deleteById(ruleId);
        ruleEngine.reloadRules();
    }

    @Transactional
    public IdsRule toggleRule(Long ruleId, boolean active) {
        IdsRule rule = ruleRepo.findById(ruleId).orElseThrow();
        rule.setActive(active);
        IdsRule saved = ruleRepo.save(rule);
        ruleEngine.reloadRules();
        return saved;
    }
}

