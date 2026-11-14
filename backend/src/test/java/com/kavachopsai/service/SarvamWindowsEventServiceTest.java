package com.kavachopsai.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.time.ZonedDateTime;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.kavachopsai.model.WindowsEventLog;

class SarvamWindowsEventServiceTest {

    @Test
    void excludesPersonalAndRawEventFieldsFromSarvamRecords() {
        WindowsEventLog event = WindowsEventLog.builder()
                .logId(12L)
                .eventId(4625L)
                .channel("Security")
                .level("Warning")
                .source("Microsoft-Windows-Security-Auditing")
                .computerName("workstation-17")
                .userName("alice")
                .eventTime(ZonedDateTime.parse("2026-03-10T12:00:00Z"))
                .message("Failed login for alice from 192.0.2.10")
                .securityRelevant(true)
                .build();

        Map<String, Object> record = new SarvamWindowsEventService().toSafeEventRecord(event);

        assertEquals(12L, record.get("logId"));
        assertEquals(4625L, record.get("eventId"));
        assertEquals("Security", record.get("channel"));
        assertEquals("Warning", record.get("level"));
        assertEquals("Microsoft-Windows-Security-Auditing", record.get("source"));
        assertEquals(true, record.get("securityRelevant"));
        assertFalse(record.containsKey("computerName"));
        assertFalse(record.containsKey("userName"));
        assertFalse(record.containsKey("message"));
    }
}
