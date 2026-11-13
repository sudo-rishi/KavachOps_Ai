package com.kavachopsai.config;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI kavachOpsAiOpenAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("KavachOps Ai Security Platform API")
                .description("""
                    Multi-Layered Defence Architecture for Maximum Network Integrity and Resilience.
                    
                    This API provides endpoints for:
                    - **Module 1** â€“ Authentication & User Management
                    - **Module 3** â€“ Real-time Network Analysis & IDS
                    - **Module 5** â€“ Malware Detection & File Integrity
                    - **Module 6** â€“ Centralized Incident Management
                    - **Module 8** â€“ Dashboard Stats & WebSocket Events
                    
                    **WebSocket Topics** (STOMP):
                    - `/topic/alerts`    â€“ Real-time IDS & Windows Event alerts
                    - `/topic/traffic`   â€“ Live packet metadata stream
                    - `/topic/events`    â€“ Windows Event Log entries
                    - `/topic/incidents` â€“ Incident creation/update events
                    - `/topic/dashboard` â€“ Aggregated stats (every 10s)
                    """)
                .version("1.0.0")
                .contact(new Contact()
                    .name("Rishikesh Kumar")
                    .email("admin@kavachopsai.local"))
                .license(new License()
                    .name("IGNOU BCA BCSP-064")))
            .servers(List.of(
                new Server().url("http://localhost:8081/api").description("Local Development")))
            .addSecurityItem(new SecurityRequirement().addList("bearerAuth"))
            .components(new Components()
                .addSecuritySchemes("bearerAuth",
                    new SecurityScheme()
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT")
                        .description("Enter JWT token from /auth/login")));
    }
}

