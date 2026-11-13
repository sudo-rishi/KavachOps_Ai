package com.kavachopsai.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService                  jwtService;
    private final KavachOpsAiUserDetailsService userDetailsService;
    private final WebAuthenticationDetailsSource detailsSource =
            new WebAuthenticationDetailsSource();         // reuse â€” it's stateless

    // â”€â”€â”€ Filter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest  request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain         filterChain
    ) throws ServletException, IOException {

        extractBearerToken(request)
                .ifPresent(jwt -> authenticate(jwt, request));

        filterChain.doFilter(request, response);
    }

    // â”€â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /** Returns the raw JWT from the Authorization header, or empty if absent/malformed. */
    private static Optional<String> extractBearerToken(HttpServletRequest request) {
        return switch (request.getHeader("Authorization")) {
            case String h when h.startsWith(BEARER_PREFIX) -> Optional.of(h.substring(BEARER_PREFIX.length()));
            case null, default                              -> Optional.empty();
        };
    }

    /** Validates the JWT and, if valid, installs the authentication into the SecurityContext. */
    private void authenticate(String jwt, HttpServletRequest request) {
        try {
            var username = jwtService.extractUsername(jwt);
            var context  = SecurityContextHolder.getContext();

            if (username != null && context.getAuthentication() == null) {
                var userDetails = userDetailsService.loadUserByUsername(username);
                if (jwtService.isTokenValid(jwt, userDetails)) {
                    context.setAuthentication(buildAuthToken(userDetails, request));
                }
            }
        } catch (Exception e) {
            log.warn("JWT authentication failed for request [{}]: {}",
                     request.getRequestURI(), e.getMessage());
        }
    }

    /** Constructs a fully-populated {@link UsernamePasswordAuthenticationToken}. */
    private UsernamePasswordAuthenticationToken buildAuthToken(
            UserDetails userDetails, HttpServletRequest request) {

        var token = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
        token.setDetails(detailsSource.buildDetails(request));
        return token;
    }
}
