package com.kavachopsai.config;

import java.util.List;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.kavachopsai.capture.IdsRuleEngine;
import com.kavachopsai.model.IdsRule;
import com.kavachopsai.repository.IdsRuleRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class IdsRulesBootstrap implements ApplicationRunner {

    private final IdsRuleRepository idsRuleRepository;
    private final IdsRuleEngine idsRuleEngine;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        List<IdsRule> defaults = predefinedRules();
        int created = 0;

        for (IdsRule rule : defaults) {
            List<IdsRule> existing = idsRuleRepository.findByRuleName(rule.getRuleName());
            if (existing.isEmpty()) {
                idsRuleRepository.save(rule);
                created++;
            } else if (existing.size() > 1) {
                log.warn("Duplicate IDS rule names found for '{}'; keeping the first and skipping additional entries.", rule.getRuleName());
            }
        }

        if (created > 0) {
            idsRuleEngine.reloadRules();
            log.info("Seeded {} predefined IDS rules.", created);
        } else {
            log.debug("Predefined IDS rules already present; no seeding needed.");
        }
    }

    private List<IdsRule> predefinedRules() {
        return List.of(
                IdsRule.builder()
                        .ruleName("RDP Brute Force Pattern")
                        .ruleContent("Detect repeated RDP attempts to TCP/3389")
                        .ruleType("custom")
                        .severity(4)
                        .sourceIpPattern(".*")
                        .destIpPattern(".*")
                        .portPattern("3389")
                        .protocolPattern("TCP")
                        .payloadPattern(".*(login|auth|cred|rdp).*")
                        .active(true)
                        .build(),
                IdsRule.builder()
                        .ruleName("SMB Lateral Movement")
                        .ruleContent("Detect SMB access over TCP/445 for potential lateral movement")
                        .ruleType("custom")
                        .severity(3)
                        .sourceIpPattern(".*")
                        .destIpPattern(".*")
                        .portPattern("445")
                        .protocolPattern("TCP")
                        .payloadPattern(".*(smb|ipc\\$|admin\\$|ntlm).*")
                        .active(true)
                        .build(),
                IdsRule.builder()
                        .ruleName("Suspicious PowerShell Download")
                        .ruleContent("Detect suspicious PowerShell web download command patterns")
                        .ruleType("custom")
                        .severity(4)
                        .sourceIpPattern(".*")
                        .destIpPattern(".*")
                        .portPattern("80,443,8080")
                        .protocolPattern("TCP")
                        .payloadPattern(".*(powershell|invoke-webrequest|iwr|downloadstring|encodedcommand).*")
                        .active(true)
                        .build(),
                IdsRule.builder()
                        .ruleName("DNS Exfiltration Heuristic")
                        .ruleContent("Detect suspicious DNS TXT/domain payload hints")
                        .ruleType("custom")
                        .severity(3)
                        .sourceIpPattern(".*")
                        .destIpPattern(".*")
                        .portPattern("53")
                        .protocolPattern("UDP|TCP")
                        .payloadPattern(".*(txt|base64|longdomain|exfil|tunnel).*")
                        .active(true)
                        .build(),
                IdsRule.builder()
                        .ruleName("Command and Control Beacon")
                        .ruleContent("Detect periodic beaconing-like HTTP C2 patterns")
                        .ruleType("custom")
                        .severity(3)
                        .sourceIpPattern(".*")
                        .destIpPattern(".*")
                        .portPattern("80,443")
                        .protocolPattern("TCP")
                        .payloadPattern(".*(beacon|heartbeat|checkin|c2|command).*")
                        .active(true)
                        .build());
    }
}

