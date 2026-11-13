package com.kavachopsai.capture;

import java.net.InetAddress;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import com.kavachopsai.model.NetworkTraffic;
import com.kavachopsai.service.NetworkAnalysisService;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class PacketCaptureEngine {

    private final NetworkAnalysisService networkAnalysisService;

    @Value("${kavachopsai.capture.interface-name:}")
    private String configuredInterface;

    @Value("${kavachopsai.capture.snap-len:65536}")
    private int snapLen;

    @Value("${kavachopsai.capture.timeout:10}")
    private int timeout;

    @Value("${kavachopsai.capture.promiscuous-mode:true}")
    private boolean promiscuousMode;

    @Value("${kavachopsai.capture.bpf-filter:}")
    private String bpfFilter;

    private PcapHandle pcapHandle;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicLong packetCount = new AtomicLong(0);
    private final AtomicLong captureLoopCount = new AtomicLong(0);
    private final AtomicLong restartCount = new AtomicLong(0);
    private final AtomicReference<ZonedDateTime> lastLoopStartedAt = new AtomicReference<>();
    private final AtomicReference<ZonedDateTime> lastPacketAt = new AtomicReference<>();
    private String activeInterface;

    // â”€â”€â”€ Lifecycle â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    @PostConstruct
    public void init() {
        log.info("PacketCaptureEngine initialized. Call startCapture() to begin.");
    }

    @PreDestroy
    public void shutdown() {
        stopCapture();
    }

    // â”€â”€â”€ Public API â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    @Async
    public void startCapture() {
        if (!running.compareAndSet(false, true)) {
            log.warn("Capture already running on interface: {}", activeInterface);
            return;
        }

        log.info("Packet capture worker started.");
        while (running.get()) {
            PcapHandle localHandle = null;
            try {
                PcapNetworkInterface nif = resolveInterface();
                if (nif == null) {
                    log.error("No valid network interface found. Capture retry in 3s.");
                    sleepQuietly(3000);
                    continue;
                }

                activeInterface = nif.getName();
                lastLoopStartedAt.set(ZonedDateTime.now());
                captureLoopCount.incrementAndGet();
                log.info("Starting packet capture loop #{} on interface: {} ({})",
                        captureLoopCount.get(),
                        nif.getName(),
                        nif.getAddresses().isEmpty() ? "no addr" : nif.getAddresses().get(0).getAddress());

                localHandle = nif.openLive(snapLen,
                        promiscuousMode ? PcapNetworkInterface.PromiscuousMode.PROMISCUOUS
                                : PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS,
                        timeout);
                pcapHandle = localHandle;

                if (bpfFilter != null && !bpfFilter.isBlank()) {
                    localHandle.setFilter(bpfFilter, BpfProgram.BpfCompileMode.OPTIMIZE);
                    log.info("BPF filter applied: {}", bpfFilter);
                }

                PacketListener packetListener = packet -> {
                    if (!running.get()) {
                        try {
                            if (pcapHandle != null) {
                                pcapHandle.breakLoop();
                            }
                        } catch (NotOpenException ignored) {
                        }
                        return;
                    }
                    try {
                        processPacket(packet);
                    } catch (Exception e) {
                        log.trace("Packet parse error: {}", e.getMessage());
                    }
                };

                localHandle.loop(-1, packetListener);

                if (running.get()) {
                    restartCount.incrementAndGet();
                    log.warn("Capture loop exited unexpectedly. Restarting capture loop (restart #{})...", restartCount.get());
                    sleepQuietly(500);
                }
            } catch (PcapNativeException e) {
                if (!running.get()) {
                    break;
                }
                restartCount.incrementAndGet();
                log.error("Pcap native error (is Npcap installed & running as Admin?): {}. Restarting...", e.getMessage());
                sleepQuietly(2000);
            } catch (NotOpenException e) {
                if (!running.get()) {
                    break;
                }
                restartCount.incrementAndGet();
                log.error("Pcap handle not open: {}. Restarting...", e.getMessage());
                sleepQuietly(1000);
            } catch (Exception e) {
                if (!running.get()) {
                    break;
                }
                restartCount.incrementAndGet();
                log.error("Capture engine error: {}", e.getMessage(), e);
                sleepQuietly(1500);
            } finally {
                if (localHandle != null && localHandle.isOpen()) {
                    try {
                        localHandle.close();
                    } catch (Exception e) {
                        log.debug("Error closing capture handle: {}", e.getMessage());
                    }
                }
                if (pcapHandle == localHandle) {
                    pcapHandle = null;
                }
            }
        }

        running.set(false);
        pcapHandle = null;
        log.info("Packet capture worker stopped.");
    }

    public void stopCapture() {
        running.set(false);
        if (pcapHandle != null && pcapHandle.isOpen()) {
            try {
                pcapHandle.breakLoop();
                log.info("Packet capture stopped. Total packets captured: {}", packetCount.get());
            } catch (Exception e) {
                log.warn("Error stopping capture: {}", e.getMessage());
            }
        }
    }

    public boolean isRunning() { return running.get(); }
    public long getPacketCount() { return packetCount.get(); }
    public long getCaptureLoopCount() { return captureLoopCount.get(); }
    public long getRestartCount() { return restartCount.get(); }
    public ZonedDateTime getLastLoopStartedAt() { return lastLoopStartedAt.get(); }
    public ZonedDateTime getLastPacketAt() { return lastPacketAt.get(); }
    public String getActiveInterface() { return activeInterface; }

    public List<String> listAvailableInterfaces() {
        try {
            return Pcaps.findAllDevs().stream()
                    .map(nif -> nif.getName() + " - " + nif.getDescription())
                    .toList();
        } catch (PcapNativeException e) {
            log.error("Cannot list interfaces: {}", e.getMessage());
            return List.of();
        }
    }

    // â”€â”€â”€ Packet Processing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    private void processPacket(Packet packet) {
        packetCount.incrementAndGet();
        lastPacketAt.set(ZonedDateTime.now());
        try {
            NetworkTraffic traffic = parsePacket(packet);
            if (traffic != null) {
                networkAnalysisService.processTraffic(traffic);
            }
        } catch (Exception e) {
            log.trace("Error processing packet: {}", e.getMessage());
        }
    }

    private void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

    private NetworkTraffic parsePacket(Packet packet) {
        NetworkTraffic.NetworkTrafficBuilder builder = NetworkTraffic.builder()
                .timestamp(ZonedDateTime.now())
                .interfaceName(activeInterface)
                .packetSize(packet.length());

        // â”€â”€ Layer 3: IP â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ipPkt = packet.get(IpV4Packet.class);
            IpV4Packet.IpV4Header hdr = ipPkt.getHeader();
            builder.sourceIp(hdr.getSrcAddr().getHostAddress())
                   .destinationIp(hdr.getDstAddr().getHostAddress())
                   .ttl((int) hdr.getTtlAsInt());

            return enrichWithTransportLayer(builder, packet, hdr.getProtocol().value());

        } else if (packet.contains(IpV6Packet.class)) {
            IpV6Packet ipPkt = packet.get(IpV6Packet.class);
            IpV6Packet.IpV6Header hdr = ipPkt.getHeader();
            builder.sourceIp(hdr.getSrcAddr().getHostAddress())
                   .destinationIp(hdr.getDstAddr().getHostAddress())
                   .protocol("IPv6");
            return enrichWithTransportLayer(builder, packet, hdr.getNextHeader().value());
        }

        return null; // non-IP packets skipped
    }

    private NetworkTraffic enrichWithTransportLayer(
            NetworkTraffic.NetworkTrafficBuilder builder, Packet packet, byte proto) {

        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcp = packet.get(TcpPacket.class);
            TcpPacket.TcpHeader hdr = tcp.getHeader();
            builder.protocol("TCP")
                   .sourcePort(hdr.getSrcPort().valueAsInt())
                   .destinationPort(hdr.getDstPort().valueAsInt())
                   .flags(buildTcpFlags(hdr));

            if (tcp.getPayload() != null) {
                byte[] payload = tcp.getPayload().getRawData();
                builder.payloadPreview(safePreview(payload));
            }

        } else if (packet.contains(UdpPacket.class)) {
            UdpPacket udp = packet.get(UdpPacket.class);
            builder.protocol("UDP")
                   .sourcePort(udp.getHeader().getSrcPort().valueAsInt())
                   .destinationPort(udp.getHeader().getDstPort().valueAsInt());

        } else if (packet.contains(IcmpV4CommonPacket.class)) {
            builder.protocol("ICMP");

        } else {
            builder.protocol("OTHER-" + String.format("0x%02X", proto));
        }

        return builder.build();
    }

    private String buildTcpFlags(TcpPacket.TcpHeader hdr) {
        StringBuilder sb = new StringBuilder();
        if (hdr.getSyn()) sb.append("SYN ");
        if (hdr.getAck()) sb.append("ACK ");
        if (hdr.getFin()) sb.append("FIN ");
        if (hdr.getRst()) sb.append("RST ");
        if (hdr.getPsh()) sb.append("PSH ");
        if (hdr.getUrg()) sb.append("URG ");
        return sb.toString().trim();
    }

    private String safePreview(byte[] data) {
        if (data == null || data.length == 0) return "";
        int len = Math.min(data.length, 100);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            char c = (char) (data[i] & 0xFF);
            sb.append(Character.isISOControl(c) ? '.' : c);
        }
        return sb.toString();
    }

    // â”€â”€â”€ Interface Resolution â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    private PcapNetworkInterface resolveInterface() throws PcapNativeException {
        List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
        if (allDevs.isEmpty()) {
            log.error("No network interfaces found. Is Npcap installed?");
            return null;
        }

        // Use configured interface name if set
        if (configuredInterface != null && !configuredInterface.isBlank()) {
            for (PcapNetworkInterface nif : allDevs) {
                if (nif.getName().equalsIgnoreCase(configuredInterface) ||
                    (nif.getDescription() != null &&
                     nif.getDescription().equalsIgnoreCase(configuredInterface))) {
                    return nif;
                }
            }
            log.warn("Configured interface '{}' not found, using auto-detection.", configuredInterface);
        }

        // Auto-select: prefer interfaces with real IP addresses, skip loopback
        for (PcapNetworkInterface nif : allDevs) {
            if (nif.isLoopBack()) continue;
            if (!nif.getAddresses().isEmpty()) {
                for (PcapAddress addr : nif.getAddresses()) {
                    InetAddress ia = addr.getAddress();
                    if (ia != null && !ia.isLoopbackAddress() && !ia.isLinkLocalAddress()) {
                        return nif;
                    }
                }
            }
        }

        // Fallback: first non-loopback
        return allDevs.stream().filter(n -> !n.isLoopBack()).findFirst()
                .orElse(allDevs.get(0));
    }
}

