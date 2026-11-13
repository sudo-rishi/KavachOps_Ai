package com.kavachopsai.repository;

import com.kavachopsai.model.CveDatabaseEntry;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CveDatabaseRepository extends JpaRepository<CveDatabaseEntry, String> {
}

