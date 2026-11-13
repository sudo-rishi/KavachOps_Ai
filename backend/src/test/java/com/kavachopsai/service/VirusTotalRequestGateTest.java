package com.kavachopsai.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Instant;

import org.junit.jupiter.api.Test;

class VirusTotalRequestGateTest {
    private static final Instant START = Instant.parse("2026-01-01T00:00:00Z");

    @Test
    void enforcesAtLeastSixteenSecondsBetweenRequests() {
        VirusTotalRequestGate gate = new VirusTotalRequestGate();

        assertEquals(VirusTotalRequestGate.Decision.ALLOWED, gate.acquire(START));
        assertEquals(
                VirusTotalRequestGate.Decision.RATE_LIMITED,
                gate.acquire(START.plusSeconds(15)));
        assertEquals(
                VirusTotalRequestGate.Decision.ALLOWED,
                gate.acquire(START.plusSeconds(16)));
    }

    @Test
    void capsLookupsWithinARollingTwentyFourHourWindow() {
        VirusTotalRequestGate gate = new VirusTotalRequestGate();

        for (int request = 0; request < 450; request++) {
            assertEquals(
                    VirusTotalRequestGate.Decision.ALLOWED,
                    gate.acquire(START.plusSeconds(request * 16L)));
        }
        assertEquals(
                VirusTotalRequestGate.Decision.DAILY_QUOTA_REACHED,
                gate.acquire(START.plusSeconds(450L * 16)));
        assertEquals(
                VirusTotalRequestGate.Decision.ALLOWED,
                gate.acquire(START.plusSeconds(24 * 60 * 60 + 1)));
    }

    @Test
    void pausesAfterProviderRateLimitAndDisablesAfterAuthFailure() {
        VirusTotalRequestGate gate = new VirusTotalRequestGate();
        gate.blockUntil(START.plusSeconds(60));

        assertEquals(VirusTotalRequestGate.Decision.COOLDOWN, gate.acquire(START));
        assertEquals(VirusTotalRequestGate.Decision.ALLOWED, gate.acquire(START.plusSeconds(60)));

        gate.disable();
        assertEquals(VirusTotalRequestGate.Decision.DISABLED, gate.acquire(START.plusSeconds(76)));
    }
}
