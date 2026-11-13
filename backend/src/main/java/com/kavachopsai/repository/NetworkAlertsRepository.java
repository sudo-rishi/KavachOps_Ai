package com.kavachopsai.repository;

import java.time.ZonedDateTime;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.kavachopsai.model.NetworkAlert;

@Repository
public interface NetworkAlertsRepository extends JpaRepository<NetworkAlert, Long> {
    org.springframework.data.domain.Page<NetworkAlert>
        findByStatusOrderByTimestampDesc(String status, org.springframework.data.domain.Pageable p);
    org.springframework.data.domain.Page<NetworkAlert>
        findBySeverityOrderByTimestampDesc(String severity, org.springframework.data.domain.Pageable p);
    org.springframework.data.domain.Page<NetworkAlert>
        findByTimestampAfterOrderByTimestampDesc(ZonedDateTime since, org.springframework.data.domain.Pageable p);
    List<NetworkAlert> findByTimestampAfterOrderByTimestampDesc(ZonedDateTime since);
    @Query("SELECT COUNT(a) FROM NetworkAlert a WHERE a.timestamp > :since")
    long countSince(@Param("since") ZonedDateTime since);
    @Query("SELECT COUNT(a) FROM NetworkAlert a WHERE a.timestamp > :since AND a.status != 'false_positive'")
    long countActiveSince(@Param("since") ZonedDateTime since);
    @Query("SELECT COUNT(a) FROM NetworkAlert a WHERE a.severity = :sev AND a.timestamp > :since")
    long countBySeveritySince(@Param("sev") String sev, @Param("since") ZonedDateTime since);
    @Query("SELECT a.severity, COUNT(a) FROM NetworkAlert a WHERE a.timestamp > :since GROUP BY a.severity")
    List<Object[]> severityStats(@Param("since") ZonedDateTime since);
    @org.springframework.data.jpa.repository.Modifying
    @Query("UPDATE NetworkAlert a SET a.status = :status WHERE a.alertId = :id")
    void updateStatus(@Param("id") Long id, @Param("status") String status);
}

