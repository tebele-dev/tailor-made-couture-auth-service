package com.tailormade.auth.util;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    @Value("${jwt.secret:mySuperSecureSecretKeyThatIsAtLeast32CharactersLong}")
    private String jwtSecret;
    
    @Autowired
    private TokenBlacklist tokenBlacklist;

    private SecretKey getSignInKey() {
        logger.debug("Getting signing key");
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    public String extractUsername(String token) {
        logger.debug("Extracting username from JWT token");
        String username = extractClaim(token, Claims::getSubject);
        logger.debug("Username extracted from token: {}", username);
        return username;
    }

    public Date extractExpiration(String token) {
        logger.debug("Extracting expiration date from JWT token");
        Date expiration = extractClaim(token, Claims::getExpiration);
        logger.debug("Token expiration date: {}", expiration);
        return expiration;
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        logger.debug("Extracting claim from JWT token");
        try {
            final Claims claims = extractAllClaims(token);
            T result = claimsResolver.apply(claims);
            logger.debug("Claim extracted successfully");
            return result;
        } catch (Exception e) {
            logger.error("Failed to extract claim from token", e);
            throw e;
        }
    }

    private Claims extractAllClaims(String token) {
        logger.debug("Parsing all claims from JWT token");
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSignInKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            logger.error("Failed to parse claims from token", e);
            throw e;
        }
    }

    private Boolean isTokenExpired(String token) {
        logger.debug("Checking if token is expired");
        Date expiration = extractExpiration(token);
        boolean expired = expiration.before(new Date());
        logger.debug("Token expired: {}", expired);
        return expired;
    }

    public String generateToken(UserDetails userDetails) {
        logger.info("Generating JWT token for user: {}", userDetails.getUsername());
        Map<String, Object> claims = new HashMap<>();
        String token = createToken(claims, userDetails.getUsername());
        logger.info("JWT token generated successfully for user: {}", userDetails.getUsername());
        return token;
    }

    public String generateToken(UserDetails userDetails, Map<String, Object> claims) {
        logger.info("Generating JWT token with custom claims for user: {}", userDetails.getUsername());
        String token = createToken(claims, userDetails.getUsername());
        logger.info("JWT token with custom claims generated successfully for user: {}", userDetails.getUsername());
        return token;
    }

    private String createToken(Map<String, Object> claims, String subject) {
        logger.debug("Creating JWT token for subject: {}", subject);
        try {
            return Jwts.builder()
                    .setClaims(claims)
                    .setSubject(subject)
                    .setIssuedAt(new Date(System.currentTimeMillis()))
                    .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                    .signWith(getSignInKey())
                    .compact();
        } catch (Exception e) {
            logger.error("Failed to create JWT token for subject: {}", subject, e);
            throw e;
        }
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        logger.info("Validating JWT token for user: {}", userDetails.getUsername());
        try {
            if (tokenBlacklist.isTokenBlacklisted(token)) {
                logger.warn("Token is blacklisted for user: {}", userDetails.getUsername());
                return false;
            }
            
            final String username = extractUsername(token);
            boolean isValid = (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
            logger.info("Token validation result for user {}: {}", userDetails.getUsername(), isValid);
            return isValid;
        } catch (Exception e) {
            logger.error("Token validation failed for user: {} - Error: {}", userDetails.getUsername(), e.getMessage(), e);
            return false;
        }
    }
    
    public String generateRefreshToken(UserDetails userDetails) {
        logger.info("Generating refresh token for user: {}", userDetails.getUsername());
        try {
            Map<String, Object> claims = new HashMap<>();
            claims.put("tokenType", "refresh");
            
            String refreshToken = Jwts.builder()
                    .setClaims(claims)
                    .setSubject(userDetails.getUsername())
                    .setIssuedAt(new Date(System.currentTimeMillis()))
                    .setExpiration(new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 7))
                    .signWith(getSignInKey())
                    .compact();
            
            logger.info("Refresh token generated successfully for user: {}", userDetails.getUsername());
            return refreshToken;
        } catch (Exception e) {
            logger.error("Failed to generate refresh token for user: {}", userDetails.getUsername(), e);
            throw e;
        }
    }
    
    public Boolean validateRefreshToken(String refreshToken) {
        logger.debug("Validating refresh token");
        try {
            final String username = extractUsername(refreshToken);
            boolean isValid = !isTokenExpired(refreshToken);
            logger.debug("Refresh token validation result: {}", isValid);
            return isValid;
        } catch (Exception e) {
            logger.error("Refresh token validation failed: {}", e.getMessage(), e);
            return false;
        }
    }
    
    public Boolean isRefreshToken(String token) {
        try {
            Claims claims = extractAllClaims(token);
            String tokenType = (String) claims.get("tokenType");
            return "refresh".equals(tokenType);
        } catch (Exception e) {
            logger.debug("Token is not a refresh token: {}", e.getMessage());
            return false;
        }
    }
    
}
