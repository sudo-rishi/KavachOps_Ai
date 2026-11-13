package com.kavachopsai.repository;

import java.time.ZonedDateTime;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.kavachopsai.model.HoneypotInteraction;

@Repository
public interface HoneypotInteractionRepository extends JpaRepository<HoneypotInteraction, Long> {
    long countByAttackerIp(String ip);
    long countByTimestampAfter(ZonedDateTime since);

    @Query("SELECT COUNT(DISTINCT h.attackerIp) FROM HoneypotInteraction h WHERE h.timestamp > :since")
    long countDistinctAttackersSince(@Param("since") ZonedDateTime since);

    @Query("SELECT h.honeypot.honeypotId, COUNT(h) FROM HoneypotInteraction h GROUP BY h.honeypot.honeypotId")
    List<Object[]> countInteractionsPerHoneypot();
}

