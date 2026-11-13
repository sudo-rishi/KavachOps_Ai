package com.kavachopsai.config;

import org.springframework.boot.ApplicationRunner;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.kavachopsai.model.User;
import com.kavachopsai.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class DefaultUserBootstrap {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${kavachopsai.bootstrap.admin.enabled:false}")
    private boolean bootstrapEnabled;

    @Value("${kavachopsai.bootstrap.admin.username:admin}")
    private String username;

    @Value("${kavachopsai.bootstrap.admin.email:admin@kavachopsai.local}")
    private String email;

    @Value("${kavachopsai.bootstrap.admin.password:}")
    private String password;

    @Bean
    public ApplicationRunner ensureDefaultAdminUser() {
        return args -> {
            if (!bootstrapEnabled) {
                log.info("Admin bootstrap is disabled.");
                return;
            }
            if (password == null || password.length() < 12) {
                throw new IllegalStateException(
                        "Set KAVACHOPSAI_BOOTSTRAP_ADMIN_PASSWORD to a unique password of at least 12 characters");
            }
            if (username == null || username.isBlank() || email == null || email.isBlank()) {
                throw new IllegalStateException("Bootstrap admin username and email must be configured");
            }
            if (userRepository.findByUsername(username).isPresent()) {
                log.info("Bootstrap admin '{}' already exists; leaving its credentials and role unchanged.", username);
                return;
            }

            User user = User.builder()
                .username(username)
                .email(email)
                .passwordHash(passwordEncoder.encode(password))
                .salt("")
                .role("admin")
                .active(true)
                .build();

            userRepository.save(user);
            log.info("Created bootstrap admin user '{}'.", username);
        };
    }
}

