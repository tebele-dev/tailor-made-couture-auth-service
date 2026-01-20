package com.tailormade.auth.controller;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.tailormade.auth.dto.AuthRequest;
import com.tailormade.auth.dto.AuthResponse;
import com.tailormade.auth.dto.ProfileUpdateRequest;
import com.tailormade.auth.dto.RefreshTokenRequest;
import com.tailormade.auth.dto.UserCreateRequest;
import com.tailormade.auth.dto.UserProfileResponse;
import com.tailormade.auth.model.User;
import com.tailormade.auth.service.UserService;
import com.tailormade.auth.util.JwtUtil;
import com.tailormade.auth.util.LoginAttemptTracker;
import com.tailormade.auth.util.TokenBlacklist;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private TokenBlacklist tokenBlacklist;

    @Autowired
    private LoginAttemptTracker loginAttemptTracker;

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public void setUserService(UserService userService) {
        this.userService = userService;
    }

    public void setJwtUtil(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    public void setTokenBlacklist(TokenBlacklist tokenBlacklist) {
        this.tokenBlacklist = tokenBlacklist;
    }

    public void setLoginAttemptTracker(LoginAttemptTracker loginAttemptTracker) {
        this.loginAttemptTracker = loginAttemptTracker;
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody AuthRequest loginRequest) {
        String email = loginRequest.getEmail();
        logger.info("Authentication attempt for email: {}", email);

        if (loginAttemptTracker.isAccountLocked(email)) {
            logger.warn("Login attempt blocked - account locked for email: {}", email);
            Map<String, String> error = new HashMap<>();
            error.put("error", loginAttemptTracker.getLockoutMessage(email));
            error.put("remainingAttempts", "0");
            return ResponseEntity.status(423).body(error);
        }

        try {
            logger.debug("Attempting authentication for user: {}", email);
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            email,
                            loginRequest.getPassword()));
            logger.info("Authentication successful for user: {}", email);

            loginAttemptTracker.recordSuccessfulAttempt(email);

            SecurityContextHolder.getContext().setAuthentication(authentication);

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            logger.debug("Generating JWT token for user: {}", userDetails.getUsername());
            String jwt = jwtUtil.generateToken(userDetails);

            logger.debug("Generating refresh token for user: {}", userDetails.getUsername());
            String refreshToken = jwtUtil.generateRefreshToken(userDetails);

            User user = userService.getUserByEmail(email);

            AuthResponse response = new AuthResponse(jwt, refreshToken, "Bearer", user.getEmail(),
                    user.getRole().toString());
            logger.info("Login successful for user: {} with role: {}", user.getEmail(), user.getRole());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.warn("Authentication failed for email: {} - Reason: {}", email, e.getMessage());

            loginAttemptTracker.recordFailedAttempt(email);

            Map<String, String> error = new HashMap<>();
            error.put("error", "Invalid credentials");
            error.put("remainingAttempts", String.valueOf(loginAttemptTracker.getRemainingAttempts(email)));

            if (loginAttemptTracker.isAccountLocked(email)) {
                error.put("locked", "true");
                error.put("lockoutMessage", loginAttemptTracker.getLockoutMessage(email));
                return ResponseEntity.status(423).body(error);
            }

            return ResponseEntity.badRequest().body(error);
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody UserCreateRequest signUpRequest) {
        logger.info("Registration attempt for email: {}", signUpRequest.getEmail());

        try {
            if (userService.emailExists(signUpRequest.getEmail())) {
                logger.warn("Registration failed - Email already exists: {}", signUpRequest.getEmail());
                Map<String, String> error = new HashMap<>();
                error.put("error", "Email is already taken!");
                return ResponseEntity.badRequest().body(error);
            }

            logger.debug("Creating new user with email: {}", signUpRequest.getEmail());
            User user = userService.createUser(signUpRequest);
            logger.info("User created successfully: {} with role: {}", user.getEmail(), user.getRole());

            logger.debug("Authenticating newly created user: {}", signUpRequest.getEmail());
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            signUpRequest.getEmail(),
                            signUpRequest.getPassword()));
            logger.debug("Authentication successful for newly created user: {}", signUpRequest.getEmail());

            SecurityContextHolder.getContext().setAuthentication(authentication);

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String jwt = jwtUtil.generateToken(userDetails);
            String refreshToken = jwtUtil.generateRefreshToken(userDetails);

            AuthResponse response = new AuthResponse(jwt, refreshToken, "Bearer", user.getEmail(),
                    user.getRole().toString());
            logger.info("Registration and login successful for user: {}", user.getEmail());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Registration failed for email: {} - Error: {}", signUpRequest.getEmail(), e.getMessage(), e);
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(HttpServletRequest request, HttpServletResponse response) {
        String userEmail = "unknown";

        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getPrincipal() instanceof UserDetails) {
                userEmail = ((UserDetails) auth.getPrincipal()).getUsername();
                logger.info("Logout initiated for user: {}", userEmail);
            }
        } catch (Exception e) {
            logger.debug("Could not retrieve user email during logout");
        }

        String token = extractTokenFromRequest(request);
        if (token != null) {
            Date expiration = extractExpirationSafely(token);
            long tokenLifetimeSeconds = 24 * 3600;

            if (expiration != null) {
                long remainingSeconds = (expiration.getTime() - System.currentTimeMillis()) / 1000;
                tokenLifetimeSeconds = Math.max(24 * 3600, remainingSeconds);
            }

            tokenBlacklist.blacklistToken(token, tokenLifetimeSeconds);
            logger.info("Token blacklisted for user: {} with duration {} seconds", userEmail, tokenLifetimeSeconds);
        }

        SecurityContextHolder.clearContext();

        Map<String, String> message = new HashMap<>();
        message.put("message", "User logged out successfully");
        logger.info("User logged out successfully: {}", userEmail);
        return ResponseEntity.ok(message);
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    private Date extractExpirationSafely(String token) {
        try {
            return jwtUtil.extractExpiration(token);
        } catch (Exception e) {
            logger.warn("Could not extract expiration from token: {}", e.getMessage());
            return null;
        }
    }

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(Authentication authentication) {
        try {
            if (authentication == null || !(authentication.getPrincipal() instanceof UserDetails)) {
                logger.warn("Unauthorized access to /me endpoint");
                return ResponseEntity.status(401).body(Map.of("error", "Unauthorized")); 
            }

            String email = ((UserDetails) authentication.getPrincipal()).getUsername();
            logger.info("Fetching profile for user: {}", email);

            User user = userService.getUserByEmail(email);
            
            UserProfileResponse response = new UserProfileResponse();
            response.setId(user.getId());
            response.setEmail(user.getEmail());
            response.setRole(user.getRole().toString());
            response.setEnabled(user.isEnabled());
            response.setCreatedAt(user.getCreatedAt());
            response.setUpdatedAt(user.getUpdatedAt());

            logger.debug("Profile fetched successfully for user: {}", email);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error fetching user profile: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(Map.of("error", "Internal server error"));
        }
    }

    @PutMapping("/me")
    public ResponseEntity<?> updateCurrentUser(@Valid @RequestBody ProfileUpdateRequest updateRequest, 
                                              Authentication authentication) {
        try {
            if (authentication == null || !(authentication.getPrincipal() instanceof UserDetails)) {
                logger.warn("Unauthorized access to update profile endpoint");
                return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
            }

            String email = ((UserDetails) authentication.getPrincipal()).getUsername();
            logger.info("Updating profile for user: {}", email);


            if (updateRequest.getNewPassword() != null && !updateRequest.getNewPassword().isEmpty()) {
                if (updateRequest.getCurrentPassword() == null || updateRequest.getCurrentPassword().isEmpty()) {
                    logger.warn("Current password required for password change");
                    return ResponseEntity.badRequest().body(Map.of("error", "Current password is required"));
                }

                try {
                    authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(email, updateRequest.getCurrentPassword())
                    );
                } catch (Exception e) {
                    logger.warn("Invalid current password for user: {}", email);
                    return ResponseEntity.badRequest().body(Map.of("error", "Current password is incorrect"));
                }
            }

            User updatedUser = userService.updateUser(email, updateRequest);
            
            UserProfileResponse response = new UserProfileResponse();
            response.setId(updatedUser.getId());
            response.setEmail(updatedUser.getEmail());
            response.setRole(updatedUser.getRole().toString());
            response.setEnabled(updatedUser.isEnabled());
            response.setCreatedAt(updatedUser.getCreatedAt());
            response.setUpdatedAt(updatedUser.getUpdatedAt());

            logger.info("Profile updated successfully for user: {}", updatedUser.getEmail());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error updating user profile: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @DeleteMapping("/me")
    public ResponseEntity<?> deleteCurrentUser(Authentication authentication) {
        try {
            if (authentication == null || !(authentication.getPrincipal() instanceof UserDetails)) {
                logger.warn("Unauthorized access to delete account endpoint");
                return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
            }

            String email = ((UserDetails) authentication.getPrincipal()).getUsername();
            logger.info("Deleting account for user: {}", email);

            userService.deleteUser(email);
            

            SecurityContextHolder.clearContext();

            Map<String, String> response = new HashMap<>();
            response.put("message", "Account deleted successfully");
            logger.info("Account deleted successfully for user: {}", email);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error deleting user account: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(Map.of("error", "Internal server error"));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody RefreshTokenRequest refreshRequest) {
        try {
            String refreshToken = refreshRequest.getRefreshToken();
            logger.info("Refresh token request received");

            if (!jwtUtil.validateRefreshToken(refreshToken)) {
                logger.warn("Invalid refresh token");
                return ResponseEntity.status(401).body(Map.of("error", "Invalid refresh token"));
            }

            String email = jwtUtil.extractUsername(refreshToken);


            UserDetails userDetails = org.springframework.security.core.userdetails.User
                .withUsername(email)
                .password("")
                .authorities("ROLE_" + userService.getUserByEmail(email).getRole().toString())
                .build();


            String newAccessToken = jwtUtil.generateToken(userDetails);
            String newRefreshToken = jwtUtil.generateRefreshToken(userDetails);

            AuthResponse response = new AuthResponse(newAccessToken, newRefreshToken, "Bearer", 
                userDetails.getUsername(), userService.getUserByEmail(email).getRole().toString());

            logger.info("Tokens refreshed successfully for user: {}", email);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error refreshing token: {}", e.getMessage(), e);
            return ResponseEntity.status(401).body(Map.of("error", "Invalid refresh token"));
        }
    }
}
