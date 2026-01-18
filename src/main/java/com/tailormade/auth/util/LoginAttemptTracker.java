package com.tailormade.auth.util;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class LoginAttemptTracker {
    
    private static final Logger logger = LoggerFactory.getLogger(LoginAttemptTracker.class);
    
    private static final int MAX_ATTEMPTS = 5;
    private static final int LOCKOUT_DURATION_MINUTES = 30;
    
    private final Map<String, LoginAttempts> attemptsMap = new ConcurrentHashMap<>();
    
    public static class LoginAttempts {
        private int attempts;
        private LocalDateTime lastAttemptTime;
        private LocalDateTime lockoutEndTime;
        
        public LoginAttempts() {
            this.attempts = 0;
            this.lastAttemptTime = LocalDateTime.now();
        }
        
        public int getAttempts() { return attempts; }
        public void setAttempts(int attempts) { this.attempts = attempts; }
        public LocalDateTime getLastAttemptTime() { return lastAttemptTime; }
        public void setLastAttemptTime(LocalDateTime lastAttemptTime) { this.lastAttemptTime = lastAttemptTime; }
        public LocalDateTime getLockoutEndTime() { return lockoutEndTime; }
        public void setLockoutEndTime(LocalDateTime lockoutEndTime) { this.lockoutEndTime = lockoutEndTime; }
    }
    
    public void recordFailedAttempt(String email) {
        logger.info("Recording failed login attempt for email: {}", email);
        
        attemptsMap.compute(email, (key, attempts) -> {
            if (attempts == null) {
                attempts = new LoginAttempts();
            }
            
            attempts.setAttempts(attempts.getAttempts() + 1);
            attempts.setLastAttemptTime(LocalDateTime.now());
            
            if (attempts.getAttempts() >= MAX_ATTEMPTS) {
                LocalDateTime lockoutEnd = LocalDateTime.now().plusMinutes(LOCKOUT_DURATION_MINUTES);
                attempts.setLockoutEndTime(lockoutEnd);
                logger.warn("Account locked for email: {} until {}", email, lockoutEnd);
            }
            
            return attempts;
        });
    }
    
    public void recordSuccessfulAttempt(String email) {
        logger.info("Recording successful login for email: {}", email);
        attemptsMap.remove(email);
    }
    
    public boolean isAccountLocked(String email) {
        LoginAttempts attempts = attemptsMap.get(email);
        if (attempts == null) {
            return false;
        }
        
        if (attempts.getLockoutEndTime() != null && 
            LocalDateTime.now().isAfter(attempts.getLockoutEndTime())) {
            logger.info("Lockout period expired for email: {}", email);
            attemptsMap.remove(email);
            return false;
        }
        
        boolean locked = attempts.getAttempts() >= MAX_ATTEMPTS;
        if (locked) {
            logger.debug("Account is locked for email: {}", email);
        }
        return locked;
    }
    
    public String getLockoutMessage(String email) {
        LoginAttempts attempts = attemptsMap.get(email);
        if (attempts == null || attempts.getLockoutEndTime() == null) {
            return "Account is temporarily locked due to multiple failed login attempts";
        }
        
        long minutesLeft = java.time.Duration.between(LocalDateTime.now(), attempts.getLockoutEndTime()).toMinutes();
        return String.format("Account is locked. Please try again in %d minutes", Math.max(1, minutesLeft));
    }
    
    public int getRemainingAttempts(String email) {
        LoginAttempts attempts = attemptsMap.get(email);
        if (attempts == null) {
            return MAX_ATTEMPTS;
        }
        return Math.max(0, MAX_ATTEMPTS - attempts.getAttempts());
    }
    
    public void cleanupExpiredEntries() {
        LocalDateTime now = LocalDateTime.now();
        attemptsMap.entrySet().removeIf(entry -> {
            LoginAttempts attempts = entry.getValue();
            return (attempts.getLockoutEndTime() != null && now.isAfter(attempts.getLockoutEndTime())) ||
                   (attempts.getAttempts() < MAX_ATTEMPTS && 
                    java.time.Duration.between(attempts.getLastAttemptTime(), now).toHours() > 24);
        });
        
        logger.debug("Cleaned up expired login attempt entries. Current tracked accounts: {}", attemptsMap.size());
    }
}