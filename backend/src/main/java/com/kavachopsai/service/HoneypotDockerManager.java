package com.kavachopsai.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

/**
 * Minimal Docker wrapper for launching disposable honeypot containers (Cowrie, Dionaea, etc.).
 * Falls back silently when Docker integration is disabled or not available.
 */
@Slf4j
@Component
public class HoneypotDockerManager {

    private final boolean dockerEnabled;
    private final String dockerBinary;
    private final String dockerNetwork;
    private final String defaultCowrieImage;
    private final String defaultDionaeaImage;
    private final String defaultConpotImage;
    private final Duration commandTimeout;

    public HoneypotDockerManager(
            @Value("${kavachopsai.honeypot.docker.enabled:false}") boolean dockerEnabled,
            @Value("${kavachopsai.honeypot.docker.binary:docker}") String dockerBinary,
            @Value("${kavachopsai.honeypot.docker.network:}") String dockerNetwork,
            @Value("${kavachopsai.honeypot.images.cowrie:cowrie/cowrie:latest}") String defaultCowrieImage,
            @Value("${kavachopsai.honeypot.images.dionaea:dtagdevsec/dionaea:latest}") String defaultDionaeaImage,
            @Value("${kavachopsai.honeypot.images.conpot:mushorg/conpot:latest}") String defaultConpotImage,
            @Value("${kavachopsai.honeypot.docker.command-timeout-seconds:30}") long commandTimeoutSeconds) {
        this.dockerEnabled = dockerEnabled;
        this.dockerBinary = dockerBinary;
        this.dockerNetwork = dockerNetwork == null ? "" : dockerNetwork.trim();
        this.defaultCowrieImage = defaultCowrieImage;
        this.defaultDionaeaImage = defaultDionaeaImage;
        this.defaultConpotImage = defaultConpotImage;
        this.commandTimeout = Duration.ofSeconds(Math.max(5, commandTimeoutSeconds));
    }

    public boolean isEnabled() {
        return dockerEnabled;
    }

    public Optional<DockerDeployment> deploy(String type, int hostPort, Integer containerPortOverride, String imageOverride) {
        if (!dockerEnabled) {
            return Optional.empty();
        }
        DockerImageProfile profile = resolveProfile(type, imageOverride, containerPortOverride);
        if (profile == null) {
            log.warn("Unknown honeypot type '{}' for Docker deployment", type);
            return Optional.empty();
        }
        if (hostPort <= 0) {
            throw new IllegalArgumentException("Host port must be > 0 for Docker honeypot deployments");
        }

        String containerName = ("kavachopsai-" + type + "-" + UUID.randomUUID().toString().substring(0, 8))
                .toLowerCase(Locale.ROOT);

        List<String> command = new ArrayList<>();
        command.add(dockerBinary);
        command.add("run");
        command.add("-d");
        command.add("--rm");
        command.add("--name");
        command.add(containerName);
        command.add("-p");
        command.add(hostPort + ":" + profile.containerPort());
        if (!dockerNetwork.isBlank()) {
            command.add("--network");
            command.add(dockerNetwork);
        }
        command.addAll(profile.extraArgs());
        command.add(profile.image());

        return execute(command).map(containerId -> {
            log.info("Started Docker honeypot '{}' ({}) on port {} -> {}", containerName,
                    profile.image(), hostPort, profile.containerPort());
            return new DockerDeployment(containerId, containerName, "127.0.0.1", hostPort, profile.image());
        });
    }

    public void stop(String containerIdOrName) {
        if (!dockerEnabled || containerIdOrName == null || containerIdOrName.isBlank()) {
            return;
        }
        List<String> command = List.of(dockerBinary, "stop", containerIdOrName);
        execute(command).ifPresent(id ->
                log.info("Stopped Docker honeypot container {}", containerIdOrName));
    }

    private DockerImageProfile resolveProfile(String type, String imageOverride, Integer containerPortOverride) {
        if (type == null || type.isBlank()) {
            return null;
        }
        String normalized = type.trim().toLowerCase(Locale.ROOT);
        DockerImageProfile base = switch (normalized) {
            case "cowrie", "ssh" -> new DockerImageProfile(defaultCowrieImage, 2222, List.of("-e", "COWRIE_TTYLOG=off"));
            case "dionaea", "ftp" -> new DockerImageProfile(defaultDionaeaImage, 21, List.of());
            case "conpot", "scada" -> new DockerImageProfile(defaultConpotImage, 102, List.of());
            default -> null;
        };
        if (base == null) {
            return null;
        }
        String image = imageOverride != null && !imageOverride.isBlank() ? imageOverride.trim() : base.image();
        int containerPort = containerPortOverride != null && containerPortOverride > 0
                ? containerPortOverride
                : base.containerPort();
        return new DockerImageProfile(image, containerPort, base.extraArgs());
    }

    private Optional<String> execute(List<String> command) {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        try {
            Process process = pb.start();
            boolean finished = process.waitFor(commandTimeout.toMillis(), java.util.concurrent.TimeUnit.MILLISECONDS);
            if (!finished) {
                process.destroyForcibly();
                log.error("Docker command timed out: {}", command);
                return Optional.empty();
            }
            int exit = process.exitValue();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String output = reader.lines().reduce("", (acc, line) -> acc + line);
                if (exit != 0) {
                    log.error("Docker command failed (exit {}): {} | output={}", exit, command, output);
                    return Optional.empty();
                }
                return Optional.ofNullable(output).filter(s -> !s.isBlank()).map(String::trim);
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            log.error("Docker command interrupted: {}", command);
            return Optional.empty();
        } catch (IOException e) {
            log.error("Docker command failed: {} -> {}", command, e.getMessage());
            return Optional.empty();
        }
    }

    public record DockerDeployment(String containerId, String containerName, String hostIp, int hostPort, String image) {}

    private record DockerImageProfile(String image, int containerPort, List<String> extraArgs) {}
}

