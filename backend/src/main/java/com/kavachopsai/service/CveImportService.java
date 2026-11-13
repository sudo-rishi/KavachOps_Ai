package com.kavachopsai.service;

import java.io.BufferedReader;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.kavachopsai.repository.CveDatabaseRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class CveImportService {

    private final JdbcTemplate jdbcTemplate;
    private final CveDatabaseRepository cveRepo;

    @Value("${kavachopsai.cve.auto-import:false}")
    private boolean autoImport;

    @Value("${kavachopsai.cve.dataset-path:dataset/nvd_vulnerabilities_with_os.csv}")
    private String datasetPath;

    private static final int BATCH_SIZE = 1000;

    @EventListener(ApplicationReadyEvent.class)
    public void importOnStartupIfNeeded() {
        if (!autoImport) {
            log.info("CVE auto import disabled.");
            return;
        }
        if (cveRepo.count() > 0) {
            log.info("CVE records already populated. Skipping auto import.");
            return;
        }

        try {
            int imported = importConfiguredDataset();
            log.info("Imported {} CVE records from dataset: {}", imported, resolveDatasetPath());
        } catch (Exception e) {
            log.warn("CVE import failed at startup: {}", e.getMessage());
        }
    }

    public int importConfiguredDataset() {
        return importFromCsv(resolveDatasetPath());
    }

    public Map<String, Object> getDatasetStatus() {
        Path path = resolveDatasetPath();
        return Map.of(
                "dataset", path.getFileName() == null ? "configured CVE dataset" : path.getFileName().toString(),
                "available", Files.isRegularFile(path),
                "recordCount", cveRepo.count(),
                "autoImport", autoImport);
    }

    public int importFromCsv(Path csvPath) {
        if (!Files.exists(csvPath)) {
            throw new IllegalArgumentException("CVE dataset not found: " + csvPath);
        }

        String sql = """
            INSERT INTO cve_records (cve_id, description, published_date, cvss_score, reference_links)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (cve_id) DO UPDATE SET
                description = COALESCE(EXCLUDED.description, cve_records.description),
                published_date = COALESCE(EXCLUDED.published_date, cve_records.published_date),
                cvss_score = COALESCE(EXCLUDED.cvss_score, cve_records.cvss_score),
                reference_links = COALESCE(EXCLUDED.reference_links, cve_records.reference_links)
            """;

        int imported = 0;
        List<CveRow> buffer = new ArrayList<>(BATCH_SIZE);

        try (BufferedReader br = Files.newBufferedReader(csvPath);
             CSVParser parser = CSVFormat.DEFAULT.builder()
                 .setHeader()
                 .setSkipHeaderRecord(true)
                 .setIgnoreEmptyLines(true)
                 .setTrim(true)
                 .build()
                 .parse(br)) {

            for (CSVRecord r : parser) {
                String cveId = firstPresent(r, "CVE ID", "CVE_ID", "CVE", "cve", "cve_id");
                if (!StringUtils.hasText(cveId)) {
                    continue;
                }
                cveId = cveId.toUpperCase(Locale.ROOT).trim();
                if (!cveId.startsWith("CVE-")) {
                    continue;
                }

                String desc = firstPresent(r, "Description", "details", "description", "desc");
                String affectedOs = firstPresent(r, "Affected OS", "affected_os");
                if (StringUtils.hasText(affectedOs)) {
                    desc = StringUtils.hasText(desc) ? desc + " Affected OS: " + affectedOs : "Affected OS: " + affectedOs;
                }
                desc = truncate(desc, 4000);
                LocalDate published = parseDate(firstPresent(r, "Published Date", "date", "published_date", "published"));
                BigDecimal cvss = parseCvss(firstPresent(r, "CVSS Score", "cvss_score", "cvss", "Severity", "severity"));
                String ref = firstPresent(r, "reference", "references", "url", "link");
                String[] refs = StringUtils.hasText(ref) ? new String[]{ref.trim()} : null;

                buffer.add(new CveRow(cveId, desc, published, cvss, refs));
                if (buffer.size() >= BATCH_SIZE) {
                    imported += executeBatch(sql, buffer);
                    buffer.clear();
                }
            }

            if (!buffer.isEmpty()) {
                imported += executeBatch(sql, buffer);
            }
        } catch (Exception e) {
            throw new IllegalStateException("Failed to import CVE CSV", e);
        }

        return imported;
    }

    private int executeBatch(String sql, List<CveRow> rows) {
        jdbcTemplate.batchUpdate(sql, rows, rows.size(), (ps, row) -> {
            ps.setString(1, row.cveId());
            ps.setString(2, row.description());
            if (row.publishedDate() == null) ps.setObject(3, null);
            else ps.setObject(3, row.publishedDate());
            if (row.cvssScore() == null) ps.setObject(4, null);
            else ps.setBigDecimal(4, row.cvssScore());
            if (row.references() == null || row.references().length == 0) {
                ps.setObject(5, null);
            } else {
                ps.setArray(5, ps.getConnection().createArrayOf("text", row.references()));
            }
        });
        return rows.size();
    }

    private String firstPresent(CSVRecord r, String... names) {
        for (String name : names) {
            if (r.isMapped(name)) {
                String value = r.get(name);
                if (StringUtils.hasText(value) && !"?".equals(value.trim())) {
                    return value;
                }
            }
        }
        return null;
    }

    private LocalDate parseDate(String raw) {
        if (!StringUtils.hasText(raw)) return null;
        String trimmed = raw.trim();
        if (trimmed.length() >= 10) {
            try {
                return LocalDate.parse(trimmed.substring(0, 10));
            } catch (DateTimeParseException ignored) {
                return null;
            }
        }
        return null;
    }

    private BigDecimal parseCvss(String raw) {
        if (!StringUtils.hasText(raw)) return null;
        try {
            BigDecimal score = new BigDecimal(raw.trim());
            if (score.compareTo(BigDecimal.ZERO) < 0 || score.compareTo(BigDecimal.TEN) > 0) {
                return null;
            }
            return score;
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    private String truncate(String text, int max) {
        if (text == null) return null;
        return text.length() <= max ? text : text.substring(0, max);
    }

    private Path resolveDatasetPath() {
        Path configured = Path.of(datasetPath);
        if (configured.isAbsolute()) {
            return configured.normalize();
        }

        Path directory = Path.of("").toAbsolutePath().normalize();
        for (Path ancestor = directory; ancestor != null; ancestor = ancestor.getParent()) {
            Path candidate = ancestor.resolve(configured).normalize();
            if (Files.isRegularFile(candidate)) {
                return candidate;
            }
        }
        return directory.resolve(configured).normalize();
    }

    private record CveRow(
        String cveId,
        String description,
        LocalDate publishedDate,
        BigDecimal cvssScore,
        String[] references
    ) {
    }
}

