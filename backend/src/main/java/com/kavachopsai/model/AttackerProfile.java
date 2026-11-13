package com.kavachopsai.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.ZonedDateTime;

@Entity
@Table(name = "attacker_profiles")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AttackerProfile {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "profile_id")
    private Integer profileId;

    @Column(name = "attacker_ip", nullable = false, unique = true, length = 45)
    private String attackerIp;

    @CreationTimestamp
    @Column(name = "first_seen", updatable = false)
    private ZonedDateTime firstSeen;

    @Column(name = "last_seen")
    private ZonedDateTime lastSeen;

    @Column(name = "threat_level", length = 20)
    @Builder.Default
    private String threatLevel = "low";
}

