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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.tailormade.auth.dto.AuthRequest;
import com.tailormade.auth.dto.AuthResponse;
import com.tailormade.auth.dto.UserCreateRequest;
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
                return ResponseEntity.status(423).body(error); // 423 Locked
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
}