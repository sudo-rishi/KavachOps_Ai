package com.kavachopsai.repository;

import com.kavachopsai.model.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.time.ZonedDateTime;
import java.util.Optional;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, String> {
    List<UserSession> findByUser_UsernameAndActiveTrue(String username);
    void deleteByUser_UsernameAndActiveTrue(String username);

    @Query("select max(s.createdAt) from UserSession s where s.user.userId = :userId")
    Optional<ZonedDateTime> findLastLoginByUserId(@Param("userId") Long userId);
}

