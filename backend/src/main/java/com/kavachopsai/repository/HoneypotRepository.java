package com.kavachopsai.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.kavachopsai.model.Honeypot;

@Repository
public interface HoneypotRepository extends JpaRepository<Honeypot, Long> {
    long countByActiveTrue();
    Optional<Honeypot> findByHoneypotName(String honeypotName);
}

