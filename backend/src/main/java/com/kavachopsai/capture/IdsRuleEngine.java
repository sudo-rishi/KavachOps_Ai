package com.kavachopsai.capture;

import com.kavachopsai.model.IdsRule;
import com.kavachopsai.model.NetworkAlert;
import com.kavachopsai.model.NetworkTraffic;
import com.kavachopsai.repository.IdsRuleRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Pattern;

/**
 * In-memory IDS Rule Engine.
 * Loads active rules from DB and matches each captured packet against them.
 * Rules are hot-reloaded every 60 seconds.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class IdsRuleEngine {

    private final IdsRuleRepository ruleRepository;

    // In-memory rule cache with compiled patterns
    private final CopyOnWriteArrayList<CompiledRule> compiledRules = new CopyOnWriteArrayList<>();

    @PostConstruct
    public void loadRules() {
        reloadRules();
        log.info("IDS Rule Engine ready with {} active rules.", compiledRules.size());
    }

    @Scheduled(fixedDelay = 60_000)
    public void reloadRules() {
        List<IdsRule> activeRules = ruleRepository.findByActiveTrue();
        List<CompiledRule> freshList = new ArrayList<>();
        for (IdsRule rule : activeRules) {
            try {
                freshList.add(new CompiledRule(rule));
            } catch (Exception e) {
                log.warn("Failed to compile rule '{}': {}", rule.getRuleName(), e.getMessage());
            }
        }
        compiledRules.clear();
        compiledRules.addAll(freshList);
        log.debug("IDS rules reloaded: {} active rules.", compiledRules.size());
    }

    /**
     * Match a traffic record against all active IDS rules.
     * Returns a list of triggered alerts (one per matching rule).
     */
    public List<NetworkAlert> match(NetworkTraffic traffic) {
        List<NetworkAlert> alerts = new ArrayList<>();
        for (CompiledRule cr : compiledRules) {
            if (matches(cr, traffic)) {
                alerts.add(buildAlert(cr.rule, traffic));
                // Increment match count (best-effort)
                cr.rule.setMatchCount(cr.rule.getMatchCount() + 1);
            }
        }
        return alerts;
    }

    private boolean matches(CompiledRule cr, NetworkTraffic t) {
        // Source IP check
        if (cr.sourceIpPattern != null && t.getSourceIp() != null) {
            if (!cr.sourceIpPattern.matcher(t.getSourceIp()).matches()) return false;
        }
        // Destination IP check
        if (cr.destIpPattern != null && t.getDestinationIp() != null) {
            if (!cr.destIpPattern.matcher(t.getDestinationIp()).matches()) return false;
        }
        // Protocol check
        if (cr.protocolPattern != null && t.getProtocol() != null) {
            if (!cr.protocolPattern.matcher(t.getProtocol()).matches()) return false;
        }
        // Port check (destination port)
        if (cr.rule.getPortPattern() != null && !cr.rule.getPortPattern().isBlank()) {
            if (!matchesPort(cr.rule.getPortPattern(), t.getDestinationPort())) return false;
        }
        // Payload check
        if (cr.payloadPattern != null && t.getPayloadPreview() != null) {
            if (!cr.payloadPattern.matcher(t.getPayloadPreview()).find()) return false;
        }
        return true;
    }

    private boolean matchesPort(String portPattern, Integer port) {
        if (port == null) return false;
        try {
            // Support ranges like "80,443" or "1-1024" or "any"
            if (portPattern.equalsIgnoreCase("any")) return true;
            if (portPattern.contains("-")) {
                String[] parts = portPattern.split("-");
                int lo = Integer.parseInt(parts[0].trim());
                int hi = Integer.parseInt(parts[1].trim());
                return port >= lo && port <= hi;
            }
            if (portPattern.contains(",")) {
                for (String p : portPattern.split(",")) {
                    if (Integer.parseInt(p.trim()) == port) return true;
                }
                return false;
            }
            return Integer.parseInt(portPattern.trim()) == port;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private NetworkAlert buildAlert(IdsRule rule, NetworkTraffic traffic) {
        String severity = mapSeverity(rule.getSeverity());
        return NetworkAlert.builder()
                .rule(rule)
                .sourceIp(traffic.getSourceIp())
                .destinationIp(traffic.getDestinationIp())
                .sourcePort(traffic.getSourcePort())
                .destinationPort(traffic.getDestinationPort())
                .protocol(traffic.getProtocol())
                .severity(severity)
                .timestamp(ZonedDateTime.now())
                .status("new")
                .alertType("IDS")
                .alertMessage(String.format("[%s] Rule '%s' triggered: %s -> %s:%s",
                        severity,
                        rule.getRuleName(),
                        traffic.getSourceIp(),
                        traffic.getDestinationIp(),
                        Optional.ofNullable(traffic.getDestinationPort()).map(String::valueOf).orElse("?")
                ))
                .packetData(traffic.getPayloadPreview())
                .build();
    }

    private String mapSeverity(int level) {
        return switch (level) {
            case 4  -> "CRITICAL";
            case 3  -> "HIGH";
            case 2  -> "MEDIUM";
            default -> "LOW";
        };
    }

    public int getRuleCount() { return compiledRules.size(); }

    // â”€â”€â”€ Inner helper: compiled rule â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    private static class CompiledRule {
        final IdsRule rule;
        final Pattern sourceIpPattern;
        final Pattern destIpPattern;
        final Pattern protocolPattern;
        final Pattern payloadPattern;

        CompiledRule(IdsRule rule) {
            this.rule = rule;
            this.sourceIpPattern  = compile(rule.getSourceIpPattern());
            this.destIpPattern    = compile(rule.getDestIpPattern());
            this.protocolPattern  = compile(rule.getProtocolPattern());
            this.payloadPattern   = compile(rule.getPayloadPattern());
        }

        private Pattern compile(String pattern) {
            if (pattern == null || pattern.isBlank() || pattern.equals("any")) return null;
            try {
                // Support CIDR-like notation by converting to regex
                String regex = pattern
                        .replace(".", "\\.")
                        .replace("*", ".*")
                        .replace("?", ".");
                return Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
            } catch (Exception e) {
                return null;
            }
        }
    }
}

