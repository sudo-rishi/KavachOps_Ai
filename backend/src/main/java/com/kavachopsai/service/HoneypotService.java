package com.kavachopsai.service;

import java.time.ZonedDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.kavachopsai.model.AttackerProfile;
import com.kavachopsai.model.Honeypot;
import com.kavachopsai.model.HoneypotInteraction;
import com.kavachopsai.repository.AttackerProfileRepository;
import com.kavachopsai.repository.HoneypotInteractionRepository;
import com.kavachopsai.repository.HoneypotRepository;
import com.kavachopsai.websocket.AlertBroadcaster;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class HoneypotService {

    private final HoneypotRepository honeypotRepo;
    private final HoneypotInteractionRepository interactionRepo;
    private final AttackerProfileRepository profileRepo;
    private final AlertBroadcaster broadcaster;
    private final HoneypotDockerManager dockerManager;

    @Transactional
    public Honeypot deployHoneypot(DeploymentOptions options) {
        String type = options.type();
        Honeypot.HoneypotBuilder builder = Honeypot.builder()
                .honeypotName(options.name())
                .honeypotType(type)
                .port(options.port())
                .active(true);

        if (options.docker()) {
            if (!dockerManager.isEnabled()) {
                throw new IllegalStateException("Docker honeypot deployment is disabled in configuration");
            }
            HoneypotDockerManager.DockerDeployment deployment = dockerManager
                    .deploy(type, options.port(), options.containerPort(), options.dockerImage())
                    .orElseThrow(() -> new IllegalStateException("Failed to start Docker honeypot for " + type));
            builder
                .deploymentType("docker")
                .ipAddress(deployment.hostIp())
                .dockerContainerId(deployment.containerId())
                .dockerImage(deployment.image())
                .lastKnownState("running");
        } else {
            String ip = requireIp(options.ipAddress());
            builder
                .deploymentType("manual")
                .ipAddress(ip)
                .lastKnownState("manual");
        }

        Honeypot saved = honeypotRepo.save(builder.build());
        log.info("Honeypot deployed: {} [{}] via {}:{} (mode={})", saved.getHoneypotName(),
                saved.getHoneypotType(), saved.getIpAddress(), saved.getPort(), saved.getDeploymentType());
        return saved;
    }

    @Transactional
    public HoneypotInteraction recordInteraction(Long honeypotId, String attackerIp, String data) {
        Honeypot hp = honeypotRepo.findById(honeypotId).orElseThrow();

        HoneypotInteraction interaction = HoneypotInteraction.builder()
            .honeypot(hp)
            .attackerIp(attackerIp)
            .data(data)
            .build();
        HoneypotInteraction saved = interactionRepo.save(interaction);

        // Update or create attacker profile
        profileRepo.findByAttackerIp(attackerIp).ifPresentOrElse(
            profile -> {
                profile.setLastSeen(ZonedDateTime.now());
                long count = interactionRepo.countByAttackerIp(attackerIp);
                profile.setThreatLevel(count > 10 ? "critical" : count > 5 ? "high" : count > 2 ? "medium" : "low");
                profileRepo.save(profile);
            },
            () -> profileRepo.save(AttackerProfile.builder()
                .attackerIp(attackerIp)
                .lastSeen(ZonedDateTime.now())
                .threatLevel("low")
                .build())
        );

        broadcaster.broadcastSystemNotification("HIGH",
            "Honeypot interaction from " + attackerIp + " on " + hp.getHoneypotName());

        return saved;
    }

    @Transactional(readOnly = true)
    public Page<HoneypotInteraction> getInteractions(int page, int size) {
        return interactionRepo.findAll(PageRequest.of(page, size, Sort.by("timestamp").descending()));
    }

    @Transactional(readOnly = true)
    public List<AttackerProfile> getTopAttackers(int limit) {
        return profileRepo.findTopByOrderByLastSeenDesc(PageRequest.of(0, limit));
    }

    @Transactional(readOnly = true)
    public Map<String, Object> getHoneypotStats() {
        ZonedDateTime last24h = ZonedDateTime.now().minusHours(24);
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("totalHoneypots",      honeypotRepo.count());
        stats.put("activeHoneypots",     honeypotRepo.countByActiveTrue());
        stats.put("interactions24h",     interactionRepo.countByTimestampAfter(last24h));
        stats.put("uniqueAttackers24h",  interactionRepo.countDistinctAttackersSince(last24h));
        return stats;
    }

    @Transactional(readOnly = true)
        public List<Honeypot> getAllHoneypots() {
        List<Honeypot> honeypots = honeypotRepo.findAll();
        Map<Long, Long> interactionCounts = interactionRepo.countInteractionsPerHoneypot()
            .stream()
            .filter(row -> row != null && row.length == 2)
            .collect(Collectors.toMap(
                row -> (Long) row[0],
                row -> (Long) row[1],
                Long::sum
            ));
        honeypots.forEach(hp -> hp.setInteractions(interactionCounts.getOrDefault(hp.getHoneypotId(), 0L)));
        return honeypots;
        }

    @Transactional
    public void deactivateHoneypot(Long id) {
        honeypotRepo.findById(id).ifPresent(hp -> {
            if ("docker".equalsIgnoreCase(hp.getDeploymentType())) {
                dockerManager.stop(Optional.ofNullable(hp.getDockerContainerId()).orElse(hp.getHoneypotName()));
                hp.setLastKnownState("stopped");
            }
            hp.setActive(false);
            honeypotRepo.save(hp);
        });
    }

    private static String requireIp(String ip) {
        if (ip == null || ip.isBlank()) {
            throw new IllegalArgumentException("ipAddress is required when docker=false");
        }
        return ip.trim();
    }

    public record DeploymentOptions(
            String name,
            String type,
            String ipAddress,
            int port,
            boolean docker,
            String dockerImage,
            Integer containerPort
    ) {}
}

