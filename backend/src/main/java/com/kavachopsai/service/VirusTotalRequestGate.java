package com.kavachopsai.service;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;

final class VirusTotalRequestGate {
    private static final Duration MINIMUM_INTERVAL = Duration.ofSeconds(16);
    private static final Duration QUOTA_WINDOW = Duration.ofHours(24);
    private static final int MAX_REQUESTS_PER_WINDOW = 450;

    enum Decision {
        ALLOWED,
        RATE_LIMITED,
        DAILY_QUOTA_REACHED,
        COOLDOWN,
        DISABLED
    }

    private final Deque<Instant> requestTimes = new ArrayDeque<>();
    private Instant lastRequestAt;
    private Instant cooldownUntil = Instant.MIN;
    private boolean disabled;

    synchronized Decision acquire(Instant now) {
        if (disabled) {
            return Decision.DISABLED;
        }
        if (now.isBefore(cooldownUntil)) {
            return Decision.COOLDOWN;
        }

        Instant windowStart = now.minus(QUOTA_WINDOW);
        while (!requestTimes.isEmpty() && !requestTimes.peekFirst().isAfter(windowStart)) {
            requestTimes.removeFirst();
        }
        if (requestTimes.size() >= MAX_REQUESTS_PER_WINDOW) {
            return Decision.DAILY_QUOTA_REACHED;
        }
        if (lastRequestAt != null && now.isBefore(lastRequestAt.plus(MINIMUM_INTERVAL))) {
            return Decision.RATE_LIMITED;
        }

        requestTimes.addLast(now);
        lastRequestAt = now;
        return Decision.ALLOWED;
    }

    synchronized void blockUntil(Instant until) {
        if (until.isAfter(cooldownUntil)) {
            cooldownUntil = until;
        }
    }

    synchronized void disable() {
        disabled = true;
    }
}
