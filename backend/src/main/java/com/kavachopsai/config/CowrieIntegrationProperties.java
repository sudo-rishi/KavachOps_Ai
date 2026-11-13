package com.kavachopsai.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Data;

/**
 * Externalized settings for ingesting Cowrie honeypot JSON logs.
 */
@Data
@Component
@ConfigurationProperties(prefix = "kavachopsai.honeypot.cowrie")
public class CowrieIntegrationProperties {
    private boolean enabled = false;
    private String logPath = "";
    private String honeypotName = "Cowrie Docker";
    private String honeypotType = "ssh";
    private String hostIp = "127.0.0.1";
    private int hostPort = 2222;
    private long pollIntervalMs = 4000;
    private boolean tailFromEnd = true;
}

