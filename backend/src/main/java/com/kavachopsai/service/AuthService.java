package com.kavachopsai.service;

import java.time.ZonedDateTime;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.kavachopsai.model.User;
import com.kavachopsai.model.UserSession;
import com.kavachopsai.repository.UserRepository;
import com.kavachopsai.repository.UserSessionRepository;
import com.kavachopsai.security.JwtService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepo;
    private final UserSessionRepository sessionRepo;
    private final JwtService jwtService;
    private final AuthenticationManager authManager;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    private static final String DEFAULT_ROLE = "analyst";

    @Transactional
    public Map<String, Object> login(String username, String password, String ipAddress, String userAgent) {
        try {
            authManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (BadCredentialsException e) {
            log.warn("Failed login attempt for user '{}' from IP {}", username, ipAddress);
            throw new BadCredentialsException("Invalid username or password");
        } catch (DisabledException e) {
            throw new DisabledException("Account is disabled");
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        User user = userRepo.findByUsernameOrEmail(username, username)
                .orElseThrow(() -> new NoSuchElementException("User not found"));

        String accessToken  = jwtService.generateToken(userDetails);
        String refreshToken = jwtService.generateRefreshToken(userDetails);

        // Store session
        UserSession session = UserSession.builder()
                .sessionId(UUID.randomUUID().toString())
                .user(user)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .expiresAt(ZonedDateTime.now().plusDays(7))
                .active(true)
                .build();
        sessionRepo.save(session);

        log.info("User '{}' logged in from IP {}", username, ipAddress);

        return Map.of(
            "accessToken",  accessToken,
            "refreshToken", refreshToken,
            "tokenType",    "Bearer",
            "expiresIn",    86400,
            "user", Map.of(
                "userId",   user.getUserId(),
                "username", user.getUsername(),
                "email",    user.getEmail(),
                "role",     user.getRole()
            )
        );
    }

    @Transactional
    public User register(String username, String email, String password) {
        if (userRepo.existsByUsername(username)) {
            throw new IllegalArgumentException("Username already taken: " + username);
        }
        if (userRepo.existsByEmail(email)) {
            throw new IllegalArgumentException("Email already registered: " + email);
        }

        String salt = BCrypt.gensalt(12);
        User user = User.builder()
                .username(username)
                .email(email)
                .passwordHash(passwordEncoder.encode(password))
                .salt(salt.substring(0, 29))
                // self-service signups are always lowest-privilege
                .role(DEFAULT_ROLE)
                .active(true)
                .build();

        User saved = userRepo.save(user);
        log.info("New user registered: {} (role: {})", username, DEFAULT_ROLE);
        return saved;
    }

    @Transactional
    public Map<String, Object> refreshToken(String refreshToken) {
        String username = jwtService.extractUsername(refreshToken);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if (!jwtService.isTokenValid(refreshToken, userDetails)) {
            throw new BadCredentialsException("Invalid refresh token");
        }
        String newAccessToken = jwtService.generateToken(userDetails);
        return Map.of("accessToken", newAccessToken, "tokenType", "Bearer");
    }

    @Transactional
    public void logout(String username) {
        sessionRepo.deleteByUser_UsernameAndActiveTrue(username);
        log.info("User '{}' logged out.", username);
    }

    @Transactional(readOnly = true)
    public User getCurrentUser(String username) {
        return userRepo.findByUsernameOrEmail(username, username)
                .orElseThrow(() -> new NoSuchElementException("User not found: " + username));
    }
}

