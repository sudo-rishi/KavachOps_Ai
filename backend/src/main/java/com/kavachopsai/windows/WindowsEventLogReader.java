package com.kavachopsai.windows;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.kavachopsai.model.WindowsEventLog;
import com.kavachopsai.service.WindowsEventService;
import com.sun.jna.Memory;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.W32Errors;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.ptr.IntByReference;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Reads Windows Event Logs from Security, System, and Application channels
 * using the Windows Event Log API (EvtQuery / EvtNext / EvtRender) via JNA.
 * Requires Windows OS. On non-Windows systems it degrades gracefully.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class WindowsEventLogReader {

    private final WindowsEventService windowsEventService;
    private final WindowsEventCatalog eventCatalog;

    @Value("${kavachopsai.events.enabled:true}")
    private boolean enabled;

    @Value("${kavachopsai.events.channels:Security,System,Application}")
    private String channelsConfig;

    @Value("${kavachopsai.events.max-events-per-poll:100}")
    private int maxEventsPerPoll;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final Object pollLock = new Object();
    private final Map<String, Long> lastReadTimestamp = new HashMap<>();

    // Security-relevant Windows Event IDs
    private static final Set<Long> SECURITY_EVENT_IDS = Set.of(
        4624L,  // Successful logon
        4625L,  // Failed logon
        4634L,  // Logoff
        4648L,  // Logon with explicit credentials
        4672L,  // Special privileges assigned
        4688L,  // Process creation
        4698L,  // Scheduled task created
        4699L,  // Scheduled task deleted
        4700L,  // Scheduled task enabled
        4701L,  // Scheduled task disabled
        4702L,  // Scheduled task updated
        4719L,  // System audit policy changed
        4720L,  // User account created
        4722L,  // User account enabled
        4725L,  // User account disabled
        4726L,  // User account deleted
        4728L,  // Member added to security-enabled global group
        4732L,  // Member added to security-enabled local group
        4738L,  // User account changed
        4740L,  // User account locked out
        4756L,  // Member added to security-enabled universal group
        4768L,  // Kerberos auth ticket requested
        4769L,  // Kerberos service ticket requested
        4771L,  // Kerberos pre-authentication failed
        4776L,  // Domain controller validated credentials
        4798L,  // User's local group membership enumerated
        4799L,  // Security-enabled local group membership enumerated
        5140L,  // Network share accessed
        5145L,  // Network share object checked
        7034L,  // Service crashed
        7035L,  // Service control sent
        7036L,  // Service started/stopped
        7045L   // New service installed
    );

    private static final boolean IS_WINDOWS =
            System.getProperty("os.name", "").toLowerCase().contains("win");

    @PostConstruct
    public void init() {
        if (!IS_WINDOWS) {
            log.warn("Windows Event Log reader disabled: not running on Windows.");
            return;
        }
        if (!enabled) {
            log.info("Windows Event Log reader disabled via config.");
            return;
        }
        running.set(true);
        log.info("Windows Event Log reader initialized. Channels: {}", channelsConfig);
        // Initialize lastRead timestamps to now (only read future events)
        for (String ch : channelsConfig.split(",")) {
            lastReadTimestamp.put(ch.trim(), System.currentTimeMillis() - 60_000L); // last 1 min on startup
        }
    }

    @PreDestroy
    public void shutdown() {
        synchronized (pollLock) {
            running.set(false);
        }
        log.info("Windows Event Log reader shutdown initiated.");
    }

    @Scheduled(fixedDelayString = "${kavachopsai.events.poll-interval-ms:5000}")
    public void pollEvents() {
        synchronized (pollLock) {
            if (!running.get() || !IS_WINDOWS) return;

            for (String channel : channelsConfig.split(",")) {
                String ch = channel.trim();
                try {
                    List<WindowsEventLog> events = readChannel(ch);
                    if (!events.isEmpty()) {
                        windowsEventService.ingestEvents(events);
                        log.debug("Ingested {} events from channel: {}", events.size(), ch);
                    }
                } catch (Exception e) {
                    log.warn("Error reading channel {}: {}", ch, e.getMessage());
                }
            }
        }
    }

    private List<WindowsEventLog> readChannel(String channel) {
        List<WindowsEventLog> results = new ArrayList<>();
        long since = lastReadTimestamp.getOrDefault(channel, System.currentTimeMillis() - 60_000L);
        long nowMs = System.currentTimeMillis();

        // Build XPath query to get events newer than last read
        // Convert epoch ms to Windows FILETIME format (100ns intervals since 1601-01-01)
        long windowsFileTime = (since + 11644473600000L) * 10000L;
        String query = String.format(
            "*[System[TimeCreated[@SystemTime >= '%s']]]",
            toW3CDateTime(since)
        );

        WinNT.HANDLE hQuery = null;
        try {
            // EvtQuery: open event query
            hQuery = Wevtapi.INSTANCE.EvtQuery(
                null,
                channel,
                query,
                Wevtapi.EvtQueryChannelPath | Wevtapi.EvtQueryForwardDirection
            );

            if (hQuery == null || hQuery == WinBase.INVALID_HANDLE_VALUE) {
                int err = Kernel32.INSTANCE.GetLastError();
                if (err == W32Errors.ERROR_EVT_CHANNEL_NOT_FOUND) {
                    log.warn("Event channel not found: {}", channel);
                }
                return results;
            }

            WinNT.HANDLE[] events = new WinNT.HANDLE[maxEventsPerPoll];
            IntByReference returned = new IntByReference(0);

            while (Wevtapi.INSTANCE.EvtNext(hQuery, maxEventsPerPoll, events, 0, 0, returned)) {
                int count = returned.getValue();
                for (int i = 0; i < count; i++) {
                    try {
                        WindowsEventLog evt = renderEvent(events[i], channel);
                        if (evt != null) results.add(evt);
                    } finally {
                        if (events[i] != null) Wevtapi.INSTANCE.EvtClose(events[i]);
                    }
                }
                if (results.size() >= maxEventsPerPoll) break;
            }

        } catch (Exception e) {
            log.error("EvtQuery error on channel {}: {}", channel, e.getMessage());
        } finally {
            if (hQuery != null && hQuery != WinBase.INVALID_HANDLE_VALUE) {
                try { Wevtapi.INSTANCE.EvtClose(hQuery); } catch (Exception ignored) {}
            }
        }

        lastReadTimestamp.put(channel, nowMs);
        return results;
    }

    private WindowsEventLog renderEvent(WinNT.HANDLE hEvent, String channel) {
        try {
            // Render event as XML
            IntByReference bufferUsed = new IntByReference(0);
            IntByReference propertyCount = new IntByReference(0);

            // First call to get required buffer size
            Wevtapi.INSTANCE.EvtRender(
                null, hEvent, Wevtapi.EvtRenderEventXml,
                0, null, bufferUsed, propertyCount
            );

            int size = bufferUsed.getValue();
            if (size <= 0) return null;

            Memory buffer = new Memory(size + 2L);
            if (!Wevtapi.INSTANCE.EvtRender(
                null, hEvent, Wevtapi.EvtRenderEventXml,
                size, buffer, bufferUsed, propertyCount
            )) {
                return null;
            }

            String xml = buffer.getWideString(0);
            return parseEventXml(xml, channel);

        } catch (Exception e) {
            log.trace("Error rendering event: {}", e.getMessage());
            return null;
        }
    }

    private WindowsEventLog parseEventXml(String xml, String channel) {
        try {
            long eventId     = extractLong(xml, "<EventID>(\\d+)</EventID>");
            String level     = mapLevel(extractLong(xml, "<Level>(\\d+)</Level>"));
            String provider  = extractStr(xml, "Name='([^']+)'");
            String computer  = extractStr(xml, "<Computer>([^<]+)</Computer>");
            String timeStr   = extractStr(xml, "SystemTime='([^']+)'");
            String userName  = extractStr(xml, "<Security UserID='([^']*)'");

            ZonedDateTime eventTime = timeStr.isEmpty()
                ? ZonedDateTime.now()
                : ZonedDateTime.parse(timeStr.replace(" ", "T").endsWith("Z")
                    ? timeStr : timeStr + "Z");

            // Extract message data from EventData
            String message = extractEventData(xml);
            var meta = eventCatalog.find(eventId).orElse(null);
            if (meta != null) {
                if (message.isEmpty()) {
                    message = meta.description();
                } else {
                    message = meta.description() + " | " + message;
                }
            }

            boolean secRelevant = SECURITY_EVENT_IDS.contains(eventId);

            return WindowsEventLog.builder()
                .eventId(eventId)
                .channel(channel)
                .level(level)
                .source(provider.isEmpty() ? (meta == null ? channel : meta.sourceName()) : provider)
                .computerName(computer)
                .userName(userName)
                .eventTime(eventTime)
                .message(message)
                .rawXml(xml.length() > 5000 ? xml.substring(0, 5000) : xml)
                .securityRelevant(secRelevant)
                .build();

        } catch (Exception e) {
            log.trace("XML parse error: {}", e.getMessage());
            return null;
        }
    }

    private long extractLong(String xml, String pattern) {
        try {
            Matcher m = Pattern.compile(pattern).matcher(xml);
            return m.find() ? Long.parseLong(m.group(1)) : 0L;
        } catch (Exception e) { return 0L; }
    }

    private String extractStr(String xml, String pattern) {
        try {
            Matcher m = Pattern.compile(pattern).matcher(xml);
            return m.find() ? m.group(1) : "";
        } catch (Exception e) { return ""; }
    }

    private String extractEventData(String xml) {
        // Pull all <Data> values into a readable string
        List<String> parts = new ArrayList<>();
        Matcher m = Pattern.compile("<Data[^>]*>([^<]*)</Data>").matcher(xml);
        while (m.find()) {
            String val = m.group(1).trim();
            if (!val.isEmpty()) parts.add(val);
        }
        return String.join(" | ", parts);
    }

    private String mapLevel(long levelCode) {
        return switch ((int) levelCode) {
            case 1  -> "Critical";
            case 2  -> "Error";
            case 3  -> "Warning";
            case 4  -> "Information";
            case 5  -> "Verbose";
            default -> "Unknown";
        };
    }

    private String toW3CDateTime(long epochMs) {
        return Instant.ofEpochMilli(epochMs)
                .atZone(ZoneId.of("UTC"))
                .toString()
                .replace("[UTC]", "");
    }

    public boolean isRunning() { return running.get() && IS_WINDOWS; }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("running", running.get());
        status.put("isWindows", IS_WINDOWS);
        status.put("enabled", enabled);
        status.put("channels", Arrays.asList(channelsConfig.split(",")));
        status.put("lastReadTimestamps", lastReadTimestamp);
        status.put("catalogEntries", eventCatalog.size());
        return status;
    }
}

