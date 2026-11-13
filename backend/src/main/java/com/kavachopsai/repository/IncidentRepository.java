package com.kavachopsai.repository;

import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.kavachopsai.model.Incident;

@Repository
public interface IncidentRepository extends JpaRepository<Incident, Long> {
    Page<Incident> findByStatusOrderByCreatedAtDesc(String status, Pageable pageable);
    Page<Incident> findBySeverityOrderByCreatedAtDesc(String severity, Pageable pageable);
    Page<Incident> findByStatusAndSeverityOrderByCreatedAtDesc(String status, String severity, Pageable pageable);
    Page<Incident> findByCreatedAtAfterOrderByCreatedAtDesc(ZonedDateTime since, Pageable pageable);
    Optional<Incident> findByIncidentNumber(String incidentNumber);

    @Query("SELECT COUNT(i) FROM Incident i WHERE i.status NOT IN ('resolved','closed')")
    long countOpenIncidents();

    @Query("SELECT i.severity, COUNT(i) FROM Incident i WHERE i.createdAt > :since GROUP BY i.severity")
    List<Object[]> severityStats(@Param("since") ZonedDateTime since);

    @Query("SELECT COUNT(i) FROM Incident i WHERE i.createdAt > :since")
    long countSince(@Param("since") ZonedDateTime since);
}

