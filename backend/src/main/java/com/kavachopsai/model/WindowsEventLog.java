package com.kavachopsai.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.ZonedDateTime;

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Windows Event Log entry
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@Entity
@Table(name = "windows_event_logs",
    indexes = {
        @Index(name = "idx_winevent_timestamp", columnList = "event_time"),
        @Index(name = "idx_winevent_id", columnList = "event_id"),
        @Index(name = "idx_winevent_channel", columnList = "channel"),
        @Index(name = "idx_winevent_level", columnList = "level")
    })
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WindowsEventLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "log_id")
    private Long logId;

    @Column(name = "event_id", nullable = false)
    private Long eventId;

    @Column(name = "channel", nullable = false, length = 100)
    private String channel; // Security, System, Application

    @Column(nullable = false, length = 20)
    private String level; // Critical, Error, Warning, Information, Verbose

    @Column(nullable = false, length = 200)
    private String source;

    @Column(name = "computer_name", length = 200)
    private String computerName;

    @Column(name = "user_name", length = 200)
    private String userName;

    @Column(nullable = false)
    private ZonedDateTime eventTime;

    @Column(name = "message", columnDefinition = "TEXT")
    private String message;

    @Column(name = "raw_xml", columnDefinition = "TEXT")
    private String rawXml;

    @Column(name = "is_security_relevant")
    @Builder.Default
    private boolean securityRelevant = false;

    @Column(name = "alert_generated")
    @Builder.Default
    private boolean alertGenerated = false;

    @CreationTimestamp
    @Column(name = "ingested_at", updatable = false)
    private ZonedDateTime ingestedAt;
}

