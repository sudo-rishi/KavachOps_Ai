package com.kavachopsai.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.ZonedDateTime;

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Network Traffic - raw captured packets
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@Entity
@Table(name = "network_traffic",
    indexes = {
        @Index(name = "idx_traffic_timestamp", columnList = "timestamp"),
        @Index(name = "idx_traffic_source_ip", columnList = "source_ip"),
        @Index(name = "idx_traffic_protocol", columnList = "protocol")
    })
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NetworkTraffic {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "traffic_id")
    private Long trafficId;

    @Column(name = "source_ip", nullable = false, length = 45)
    private String sourceIp;

    @Column(name = "destination_ip", nullable = false, length = 45)
    private String destinationIp;

    @Column(name = "source_port")
    private Integer sourcePort;

    @Column(name = "destination_port")
    private Integer destinationPort;

    @Column(nullable = false, length = 20)
    private String protocol;

    @Column(name = "packet_size")
    private Integer packetSize;

    @Column(name = "flags", length = 50)
    private String flags;

    @Column(name = "ttl")
    private Integer ttl;

    @Column(nullable = false)
    private ZonedDateTime timestamp;

    @Column(name = "payload_preview", length = 500)
    private String payloadPreview;

    @Column(name = "interface_name", length = 50)
    private String interfaceName;
}

