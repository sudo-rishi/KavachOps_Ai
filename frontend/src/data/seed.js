/**
 * KavachOps AI reference data and frontend-only demo examples.
 */

export const EVENT_ID_NAMES = {
  4625:'Failed Logon', 4624:'Successful Logon', 7045:'New Service', 4688:'Process Created',
  4740:'Account Locked', 4720:'User Created', 4698:'Task Created', 4719:'Policy Changed',
  4672:'Special Privileges', 4636:'Logoff', 5140:'Share Accessed',
};

export function createDemoData(now = Date.now()) {
  const ago = (minutes) => new Date(now - minutes * 60_000).toISOString();
  const demo = (record) => ({ ...record, _demo: true });

  const alerts = [
    demo({
      alertId: "demo-alert-1", alertType: "BRUTE_FORCE", severity: "HIGH", status: "new",
      alertMessage: "Repeated SSH authentication failures detected",
      sourceIp: "198.51.100.24", destinationIp: "192.0.2.10", sourcePort: 51142,
      destinationPort: 22, protocol: "TCP", timestamp: ago(12),
    }),
    demo({
      alertId: "demo-alert-2", alertType: "DNS_ANOMALY", severity: "MEDIUM", status: "new",
      alertMessage: "Unusually long DNS query observed",
      sourceIp: "192.0.2.45", destinationIp: "192.0.2.53", sourcePort: 53530,
      destinationPort: 53, protocol: "UDP", timestamp: ago(38),
    }),
    demo({
      alertId: "demo-alert-3", alertType: "PORT_SCAN", severity: "CRITICAL", status: "investigating",
      alertMessage: "Sequential connection attempts across protected services",
      sourceIp: "203.0.113.77", destinationIp: "192.0.2.20", sourcePort: 42001,
      destinationPort: 445, protocol: "TCP", timestamp: ago(77),
    }),
  ];

  const incidents = [
    demo({
      incidentId: "demo-incident-1", incidentNumber: "DEMO-2026-001",
      title: "Repeated SSH authentication failures", severity: "high", status: "investigating",
      category: "Brute Force", assignedTo: "demo.analyst", affectedAssets: "192.0.2.10",
      description: "Synthetic example incident associated with the sample network alert.",
      createdAt: ago(25),
    }),
    demo({
      incidentId: "demo-incident-2", incidentNumber: "DEMO-2026-002",
      title: "Suspicious DNS query pattern", severity: "medium", status: "open",
      category: "Network Anomaly", assignedTo: "Unassigned", affectedAssets: "192.0.2.45",
      description: "Synthetic example incident for dashboard and workflow previews.",
      createdAt: ago(90),
    }),
  ];

  const winEvents = [
    demo({
      logId: "demo-event-1", eventId: 4625, channel: "Security", level: "Warning",
      securityRelevant: true, eventTime: ago(9), userName: "demo-user",
      computerName: "DEMO-WKS-01", source: "Microsoft-Windows-Security-Auditing",
      message: "[Failed Logon] A sample account failed authentication.",
    }),
    demo({
      logId: "demo-event-2", eventId: 7045, channel: "System", level: "Error",
      securityRelevant: true, eventTime: ago(46), userName: "SYSTEM",
      computerName: "DEMO-SRV-01", source: "Service Control Manager",
      message: "[New Service] A sample service installation event.",
    }),
    demo({
      logId: "demo-event-3", eventId: 4624, channel: "Security", level: "Information",
      securityRelevant: false, eventTime: ago(105), userName: "demo.analyst",
      computerName: "DEMO-WKS-01", source: "Microsoft-Windows-Security-Auditing",
      message: "[Successful Logon] A sample interactive logon event.",
    }),
  ];

  const malwareScans = [
    demo({
      scanId: "demo-malware-1", fileName: "sample_suspicious.exe",
      fileHash: "0".repeat(64), fileSize: 184320, scanEngine: "HEURISTIC+YARA",
      scanResult: "suspicious", threatName: "Demo.Suspicious.Sample",
      yaraRuleMatched: "DEMO_SUSPICIOUS_FILE", virustotalPositives: 2,
      virustotalTotal: 70, quarantined: false, scanTime: ago(31),
    }),
    demo({
      scanId: "demo-malware-2", fileName: "sample_document.pdf",
      fileHash: "1".repeat(64), fileSize: 67210, scanEngine: "HEURISTIC",
      scanResult: "clean", threatName: null, yaraRuleMatched: null,
      virustotalPositives: 0, virustotalTotal: 70, quarantined: false, scanTime: ago(142),
    }),
    demo({
      scanId: "demo-malware-3", fileName: "sample_quarantined.bin",
      fileHash: "2".repeat(64), fileSize: 98304, scanEngine: "HEURISTIC+YARA",
      scanResult: "infected", threatName: "Demo.Test.Detection",
      yaraRuleMatched: "DEMO_TEST_SIGNATURE", virustotalPositives: 8,
      virustotalTotal: 70, quarantined: true, quarantinePath: "DEMO_ONLY/sample_quarantined.bin",
      scanTime: ago(205),
    }),
  ];

  const idsRules = [
    demo({
      ruleId: "demo-rule-1", ruleName: "Demo SSH Rate Pattern",
      ruleContent: "Synthetic preview rule; no live packet matching is performed.",
      ruleType: "custom", severity: 3, sourceIpPattern: ".*", destIpPattern: ".*",
      portPattern: "22", protocolPattern: "TCP", payloadPattern: ".*", active: true,
    }),
    demo({
      ruleId: "demo-rule-2", ruleName: "Demo DNS Query Pattern",
      ruleContent: "Synthetic preview rule; no live packet matching is performed.",
      ruleType: "custom", severity: 2, sourceIpPattern: ".*", destIpPattern: ".*",
      portPattern: "53", protocolPattern: "UDP", payloadPattern: ".*", active: false,
    }),
  ];

  const vulnFindings = [
    demo({
      findingId: "demo-finding-1", hostIp: "192.0.2.20",
      vulnerabilityName: "Sample TLS configuration requires review",
      cveId: null, cvssScore: 8.1, severity: "high", status: "open",
      discoveredAt: ago(55),
    }),
    demo({
      findingId: "demo-finding-2", hostIp: "192.0.2.30",
      vulnerabilityName: "Sample outdated web component",
      cveId: null, cvssScore: 5.4, severity: "medium", status: "in_progress",
      discoveredAt: ago(260),
    }),
  ];

  const vulnScans = [
    demo({
      scanId: "demo-vuln-scan-1", scanName: "Demo internal network review",
      scanType: "network", targets: "192.0.2.0/24", startTime: ago(180),
      scanStatus: "completed",
    }),
    demo({
      scanId: "demo-vuln-scan-2", scanName: "Demo web service check",
      scanType: "web", targets: "https://demo.example.invalid", startTime: ago(48),
      scanStatus: "completed",
    }),
  ];

  const honeypots = [
    demo({
      honeypotId: "demo-honeypot-1", honeypotName: "Demo SSH Trap",
      honeypotType: "ssh", ipAddress: "192.0.2.80", port: 2222,
      interactions: 18, active: true,
    }),
    demo({
      honeypotId: "demo-honeypot-2", honeypotName: "Demo Web Trap",
      honeypotType: "http", ipAddress: "192.0.2.81", port: 8080,
      interactions: 7, active: true,
    }),
  ];

  const attackers = [
    demo({
      ip: "198.51.100.24", threatLevel: "high", country: "Sample",
      interactions: 13, firstSeen: ago(1440), lastSeen: ago(12),
    }),
    demo({
      ip: "203.0.113.77", threatLevel: "critical", country: "Sample",
      interactions: 9, firstSeen: ago(720), lastSeen: ago(77),
    }),
  ];

  const users = [
    demo({
      userId: "demo-user-1", username: "demo.analyst",
      email: "analyst@example.invalid", role: "analyst", active: true,
      createdAt: ago(60 * 24 * 30), lastLogin: ago(45),
    }),
    demo({
      userId: "demo-user-2", username: "demo.auditor",
      email: "auditor@example.invalid", role: "auditor", active: true,
      createdAt: ago(60 * 24 * 14), lastLogin: null,
    }),
  ];

  const trafficFeed = [
    demo({ time: ago(3), src: "192.0.2.15", dst: "192.0.2.10", protocol: "TCP", port: 443, size: 1240, anomalyScore: null }),
    demo({ time: ago(8), src: "198.51.100.24", dst: "192.0.2.10", protocol: "TCP", port: 22, size: 512, anomalyScore: -0.31 }),
    demo({ time: ago(16), src: "192.0.2.45", dst: "192.0.2.53", protocol: "UDP", port: 53, size: 178, anomalyScore: -0.12 }),
    demo({ time: ago(29), src: "192.0.2.30", dst: "192.0.2.20", protocol: "TCP", port: 445, size: 1460, anomalyScore: null }),
  ];

  return {
    alerts,
    incidents,
    winEvents,
    malwareScans,
    idsRules,
    vulnFindings,
    vulnScans,
    honeypots,
    attackers,
    users,
    trafficFeed,
    feedItems: alerts.map((alert) => demo({
      time: alert.timestamp,
      severity: alert.severity,
      label: alert.alertType,
      message: alert.alertMessage,
    })),
  };
}
