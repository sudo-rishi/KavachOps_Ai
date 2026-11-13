package com.kavachopsai.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.kavachopsai.model.IdsRule;

@Repository
public interface IdsRuleRepository extends JpaRepository<IdsRule, Long> {
    List<IdsRule> findByActiveTrue();
    List<IdsRule> findBySeverityGreaterThanEqualAndActiveTrue(int minSeverity);
    List<IdsRule> findByRuleName(String ruleName);
}

