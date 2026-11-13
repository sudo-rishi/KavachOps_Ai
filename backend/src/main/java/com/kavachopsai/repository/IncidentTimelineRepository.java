package com.kavachopsai.repository;

import com.kavachopsai.model.IncidentTimeline;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface IncidentTimelineRepository extends JpaRepository<IncidentTimeline, Long> {
    List<IncidentTimeline> findByIncident_IncidentIdOrderByTimestampAsc(Long incidentId);
}

