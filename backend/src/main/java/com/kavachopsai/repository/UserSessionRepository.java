package com.kavachopsai.repository;

import com.kavachopsai.model.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, String> {
    List<UserSession> findByUser_UsernameAndActiveTrue(String username);
    void deleteByUser_UsernameAndActiveTrue(String username);
}

