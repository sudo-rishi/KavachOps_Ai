package com.kavachopsai.config;

import org.springframework.boot.ApplicationRunner;
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

    @Bean
    public ApplicationRunner ensureDefaultAdminUser() {
        return args -> {
            String username = "admin";
            String email = "admin@kavachopsai.local";
            String password = "password";

            if (userRepository.findByUsername(username).isPresent()) {
                User existing = userRepository.findByUsername(username).get();
                if (!passwordEncoder.matches(password, existing.getPasswordHash())) {
                    existing.setPasswordHash(passwordEncoder.encode(password));
                    existing.setRole("admin");
                    existing.setActive(true);
                    userRepository.save(existing);
                    log.info("Updated default admin password to the documented value.");
                }
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
            log.info("Created default admin user: {} / password", username);
        };
    }
}

