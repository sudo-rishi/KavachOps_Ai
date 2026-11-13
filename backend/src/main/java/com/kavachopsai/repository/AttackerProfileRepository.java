package com.kavachopsai.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.kavachopsai.model.AttackerProfile;

@Repository
public interface AttackerProfileRepository extends JpaRepository<AttackerProfile, Integer> {
    Optional<AttackerProfile> findByAttackerIp(String ip);
    List<AttackerProfile> findTopByOrderByLastSeenDesc(Pageable pageable);
}

