package com.kavachopsai.dto;

/**
 * Lightweight DTO used by the reporting API to surface data validation checks.
 */
public record ReportChecklistItem(
        String id,
        String label,
        String status,
        String detail
) {}

