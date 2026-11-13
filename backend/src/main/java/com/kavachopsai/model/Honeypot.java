package com.kavachopsai.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

// â”€â”€â”€ Honeypot â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@Entity
@Table(name = "honeypots")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Honeypot {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "honeypot_id")
    private Long honeypotId;

    @Column(name = "honeypot_name", nullable = false, length = 200)
    private String honeypotName;

    @Column(name = "honeypot_type", nullable = false, length = 20)
    private String honeypotType;

    @Column(name = "ip_address", nullable = false, length = 45)
    private String ipAddress;

    @Column(nullable = false)
    private Integer port;

    @Column(name = "deployment_type", length = 20)
    @Builder.Default
    private String deploymentType = "manual";   // manual | docker

    @Column(name = "docker_container_id", length = 64)
    private String dockerContainerId;

    @Column(name = "docker_image", length = 120)
    private String dockerImage;

    @Column(name = "last_known_state", length = 30)
    private String lastKnownState;

    @Column(name = "is_active", nullable = false)
    @Builder.Default
    private boolean active = true;

    @Transient
    private long interactions;
}

