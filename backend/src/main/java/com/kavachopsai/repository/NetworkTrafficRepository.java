package com.kavachopsai.repository;

import com.kavachopsai.model.NetworkTraffic;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.ZonedDateTime;
import java.util.List;

@Repository
public interface NetworkTrafficRepository extends JpaRepository<NetworkTraffic, Long> {
    Page<NetworkTraffic> findByTimestampBetween(ZonedDateTime from, ZonedDateTime to, Pageable pageable);
    Page<NetworkTraffic> findBySourceIpOrderByTimestampDesc(String sourceIp, Pageable pageable);

    @Query("SELECT COUNT(n) FROM NetworkTraffic n WHERE n.timestamp > :since")
    long countSince(@Param("since") ZonedDateTime since);

    @Query("SELECT n.protocol, COUNT(n) FROM NetworkTraffic n WHERE n.timestamp > :since GROUP BY n.protocol ORDER BY COUNT(n) DESC")
    List<Object[]> protocolStats(@Param("since") ZonedDateTime since);

    @Query("SELECT n.sourceIp, COUNT(n) as cnt FROM NetworkTraffic n WHERE n.timestamp > :since GROUP BY n.sourceIp ORDER BY cnt DESC")
    List<Object[]> topSourceIps(@Param("since") ZonedDateTime since, Pageable pageable);
}

