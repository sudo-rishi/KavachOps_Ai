package com.kavachopsai.repository;

import java.time.ZonedDateTime;
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.kavachopsai.model.WindowsEventLog;

@Repository
public interface WindowsEventLogRepository extends JpaRepository<WindowsEventLog, Long> {
    Page<WindowsEventLog> findByChannelOrderByEventTimeDesc(String channel, Pageable pageable);
    Page<WindowsEventLog> findByLevelOrderByEventTimeDesc(String level, Pageable pageable);
    Page<WindowsEventLog> findByEventTimeAfterOrderByEventTimeDesc(ZonedDateTime since, Pageable pageable);
    List<WindowsEventLog> findBySecurityRelevantTrueOrderByEventTimeDesc(Pageable pageable);

    @Query("SELECT COUNT(w) FROM WindowsEventLog w WHERE w.eventTime > :since")
    long countSince(@Param("since") ZonedDateTime since);

    @Query("SELECT COUNT(w) FROM WindowsEventLog w WHERE w.securityRelevant = true AND w.eventTime > :since")
    long countSecurityEventsSince(@Param("since") ZonedDateTime since);

    @Query("SELECT w.eventId, COUNT(w) FROM WindowsEventLog w WHERE w.eventTime > :since GROUP BY w.eventId ORDER BY COUNT(w) DESC")
    List<Object[]> topEventIds(@Param("since") ZonedDateTime since, Pageable pageable);

    List<WindowsEventLog> findByEventTimeAfterOrderByEventTimeDesc(ZonedDateTime since);
}

