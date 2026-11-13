package com.kavachopsai.repository;

import com.kavachopsai.model.CveDatabaseEntry;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CveDatabaseRepository extends JpaRepository<CveDatabaseEntry, String> {

    @Query("""
        SELECT c FROM CveDatabaseEntry c
        WHERE LOWER(c.cveId) LIKE LOWER(CONCAT('%', :query, '%'))
           OR LOWER(COALESCE(c.description, '')) LIKE LOWER(CONCAT('%', :query, '%'))
        """)
    Page<CveDatabaseEntry> search(@Param("query") String query, Pageable pageable);
}

