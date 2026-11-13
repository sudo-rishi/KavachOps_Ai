package com.kavachopsai.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.ZonedDateTime;

@Entity
@Table(name = "honeypot_interactions",
    indexes = @Index(name = "idx_honeypot_ts", columnList = "timestamp"))
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class HoneypotInteraction {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "interaction_id")
    private Long interactionId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "honeypot_id")
    @ToString.Exclude
    private Honeypot honeypot;

    @Column(name = "attacker_ip", nullable = false, length = 45)
    private String attackerIp;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private ZonedDateTime timestamp;

    @Column(columnDefinition = "TEXT")
    private String data;
}

