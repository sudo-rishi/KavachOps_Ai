package com.kavachopsai.controller;

import java.time.ZonedDateTime;
import java.util.List;
import java.util.NoSuchElementException;

import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.kavachopsai.model.User;
import com.kavachopsai.repository.UserRepository;
import com.kavachopsai.repository.UserSessionRepository;
import com.kavachopsai.service.AuthService;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/admin/users")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminUserController {

    private final UserRepository userRepository;
    private final UserSessionRepository userSessionRepository;
    private final AuthService authService;

    @GetMapping
    public List<UserView> listUsers() {
        return userRepository.findAll(Sort.by(Sort.Direction.ASC, "username"))
                .stream()
                .map(this::toView)
                .toList();
    }

    @PostMapping
    public ResponseEntity<UserView> createUser(@Valid @RequestBody CreateUserRequest request) {
        User user = authService.createManagedUser(
                request.username().trim(),
                request.email().trim(),
                request.password(),
                request.role());
        return ResponseEntity.status(HttpStatus.CREATED).body(toView(user));
    }

    @PatchMapping("/{userId}/active")
    public UserView setUserActive(
            @PathVariable Long userId,
            @Valid @RequestBody SetActiveRequest request,
            @AuthenticationPrincipal UserDetails currentUser) {
        User target = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        if (!request.active() && target.getUsername().equals(currentUser.getUsername())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "You cannot disable your own account");
        }
        try {
            return toView(authService.setUserActive(userId, request.active()));
        } catch (NoSuchElementException ex) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found", ex);
        }
    }

    private UserView toView(User user) {
        return new UserView(
                user.getUserId(),
                user.getUsername(),
                user.getEmail(),
                user.getRole(),
                user.isActive(),
                user.getCreatedAt(),
                userSessionRepository.findLastLoginByUserId(user.getUserId()).orElse(null));
    }

    public record CreateUserRequest(
            @NotBlank @Size(min = 3, max = 50) String username,
            @NotBlank @Email @Size(max = 100) String email,
            @NotBlank @Size(min = 8, max = 100) String password,
            @NotBlank @Pattern(regexp = "(?i)(admin|analyst|operator|auditor|viewer)") String role) {
    }

    public record SetActiveRequest(@NotNull Boolean active) {
    }

    public record UserView(
            Long userId,
            String username,
            String email,
            String role,
            boolean active,
            ZonedDateTime createdAt,
            ZonedDateTime lastLogin) {
    }
}
