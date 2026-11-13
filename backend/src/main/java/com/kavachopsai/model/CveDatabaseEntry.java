package com.kavachopsai.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDate;

@Entity
@Table(name = "cve_records")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CveDatabaseEntry {

    @Id
    @Column(name = "cve_id", length = 20)
    private String cveId;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @Column(name = "published_date")
    private LocalDate publishedDate;

    @Column(name = "cvss_score", precision = 3, scale = 1)
    private BigDecimal cvssScore;

    @Column(name = "reference_links", columnDefinition = "TEXT[]")
    private String[] referenceLinks;
}

