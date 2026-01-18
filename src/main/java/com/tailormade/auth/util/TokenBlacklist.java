package com.tailormade.auth.util;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class TokenBlacklist {
    
    private static final Logger logger = LoggerFactory.getLogger(TokenBlacklist.class);
    
    private final Map<String, Instant> blacklistedTokens = new ConcurrentHashMap<>();
    
    public void blacklistToken(String token) {
        logger.info("Blacklisting token");
        Instant expiryTime = Instant.now().plusSeconds(24 * 3600); 
        blacklistedTokens.put(token, expiryTime);
    }
    
    public void blacklistToken(String token, long durationInSeconds) {
        logger.info("Blacklisting token for {} seconds", durationInSeconds);
        Instant expiryTime = Instant.now().plusSeconds(durationInSeconds); 
        blacklistedTokens.put(token, expiryTime);
    }
    
    public boolean isTokenBlacklisted(String token) {
        if (token == null) {
            return false;
        }
        
        Instant expiryTime = blacklistedTokens.get(token);
        
        if (expiryTime == null) {
            return false;
        }
        
        if (Instant.now().isAfter(expiryTime)) {
            blacklistedTokens.remove(token);
            logger.debug("Removed expired token from blacklist: {}", token);
            return false;
        }
        
        logger.debug("Token found in blacklist: {}", token);
        return true;
    }
    
    public void removeExpiredTokens() {
        Instant now = Instant.now();
        blacklistedTokens.entrySet().removeIf(entry -> now.isAfter(entry.getValue()));
        logger.info("Cleaned up expired tokens. Remaining blacklist size: {}", blacklistedTokens.size());
    }
}