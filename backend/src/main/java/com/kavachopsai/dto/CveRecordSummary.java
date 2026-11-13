package com.kavachopsai.dto;

import java.math.BigDecimal;
import java.time.ZonedDateTime;

/**
 * Aggregated view of CVE usage inside vulnerability findings.
 */
public record CveRecordSummary(
        String cveId,
        long totalFindings,
        long criticalCount,
        long highCount,
        long mediumCount,
        long lowCount,
        BigDecimal cvssScore,
        String description,
        ZonedDateTime lastObserved
) {
    public String prominence() {
        if (criticalCount > 0) return "critical";
        if (highCount > 0) return "high";
        if (mediumCount > 0) return "medium";
        if (lowCount > 0) return "low";
        return "info";
    }
}

