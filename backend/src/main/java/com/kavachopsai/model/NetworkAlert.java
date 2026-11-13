package com.kavachopsai.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.ZonedDateTime;

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Network Alert
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@Entity
@Table(name = "network_alerts",
    indexes = {
        @Index(name = "idx_alert_timestamp", columnList = "timestamp"),
        @Index(name = "idx_alert_severity", columnList = "severity"),
        @Index(name = "idx_alert_status", columnList = "status")
    })
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NetworkAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "alert_id")
    private Long alertId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "rule_id")
    @ToString.Exclude
    private IdsRule rule;

    @Column(name = "source_ip", nullable = false, length = 45)
    private String sourceIp;

    @Column(name = "destination_ip", nullable = false, length = 45)
    private String destinationIp;

    @Column(name = "source_port")
    private Integer sourcePort;

    @Column(name = "destination_port")
    private Integer destinationPort;

    @Column(nullable = false, length = 20)
    private String severity; // LOW, MEDIUM, HIGH, CRITICAL

    @Column(nullable = false)
    private ZonedDateTime timestamp;

    @Column(length = 20)
    @Builder.Default
    private String status = "new"; // new, investigating, resolved, false_positive

    @Column(name = "alert_message", length = 1000)
    private String alertMessage;

    @Column(name = "protocol", length = 20)
    private String protocol;

    @Column(name = "packet_data", columnDefinition = "TEXT")
    private String packetData;

    @Column(name = "alert_type", length = 50)
    private String alertType; // IDS, ANOMALY, WINDOWS_EVENT
}

