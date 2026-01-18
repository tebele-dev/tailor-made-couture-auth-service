package com.tailormade.auth.util;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@ExtendWith(MockitoExtension.class)
class JwtUtilTest {

    @Mock
    private TokenBlacklist tokenBlacklist;

    @InjectMocks
    private JwtUtil jwtUtil;

    private String validToken;
    private String refreshToken;
    private String secretKey = "mySuperSecureSecretKeyThatIsAtLeast32CharactersLong";

    @BeforeEach
    void setUp() throws Exception {
        Field secretField = JwtUtil.class.getDeclaredField("jwtSecret");
        secretField.setAccessible(true);
        secretField.set(jwtUtil, secretKey);
        
        validToken = Jwts.builder()
                .setSubject("test@example.com")
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .compact();
                
        refreshToken = Jwts.builder()
                .setClaims(Map.of("tokenType", "refresh"))
                .setSubject("test@example.com")
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 7))
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .compact();
    }

    private UserDetails createUserDetails(String username) {
        UserDetails userDetails = mock(UserDetails.class);
        lenient().when(userDetails.getUsername()).thenReturn(username);
        return userDetails;
    }

    @Test
    void extractUsername_success() {
        String username = jwtUtil.extractUsername(validToken);

        assertThat(username).isEqualTo("test@example.com");
    }

    @Test
    void extractExpiration_success() {
        Date expiration = jwtUtil.extractExpiration(validToken);

        assertThat(expiration).isNotNull();
        assertThat(expiration).isAfter(new Date());
    }

    @Test
    void extractClaim_success() {
        String subject = jwtUtil.extractClaim(validToken, Claims::getSubject);

        assertThat(subject).isEqualTo("test@example.com");
    }

    @Test
    void generateToken_withoutCustomClaims() {
        UserDetails testUser = createUserDetails("test@example.com");
        
        String token = jwtUtil.generateToken(testUser);

        assertThat(token).isNotNull();
        assertThat(token).isNotBlank();
        String extractedUsername = jwtUtil.extractUsername(token);
        assertThat(extractedUsername).isEqualTo("test@example.com");
    }

    @Test
    void generateToken_withCustomClaims() {
        UserDetails testUser = createUserDetails("test@example.com");
        Map<String, Object> claims = new HashMap<>();
        claims.put("customClaim", "customValue");

        String token = jwtUtil.generateToken(testUser, claims);

        assertThat(token).isNotNull();
        assertThat(token).isNotBlank();
    }

    @Test
    void validateToken_validToken_returnsTrue() {
        UserDetails testUser = createUserDetails("test@example.com");
        when(tokenBlacklist.isTokenBlacklisted(anyString())).thenReturn(false);

        boolean isValid = jwtUtil.validateToken(validToken, testUser);

        assertThat(isValid).isTrue();
        verify(tokenBlacklist).isTokenBlacklisted(validToken);
    }

    @Test
    void validateToken_blacklistedToken_returnsFalse() {
        UserDetails testUser = createUserDetails("test@example.com");
        when(tokenBlacklist.isTokenBlacklisted(anyString())).thenReturn(true);

        boolean isValid = jwtUtil.validateToken(validToken, testUser);

        assertThat(isValid).isFalse();
        verify(tokenBlacklist).isTokenBlacklisted(validToken);
    }

    @Test
    void validateToken_wrongUsername_returnsFalse() {
        UserDetails testUser = createUserDetails("test@example.com");
        UserDetails differentUser = createUserDetails("different@example.com");
        when(tokenBlacklist.isTokenBlacklisted(anyString())).thenReturn(false);

        boolean isValid = jwtUtil.validateToken(validToken, differentUser);

        assertThat(isValid).isFalse();
    }

    @Test
    void validateToken_expiredToken_returnsFalse() {
        UserDetails testUser = createUserDetails("test@example.com");
        String expiredToken = Jwts.builder()
                .setSubject("test@example.com")
                .setIssuedAt(new Date(System.currentTimeMillis() - 1000 * 60 * 60 * 24))
                .setExpiration(new Date(System.currentTimeMillis() - 1000 * 60 * 60))
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .compact();
        when(tokenBlacklist.isTokenBlacklisted(anyString())).thenReturn(false);

        boolean isValid = jwtUtil.validateToken(expiredToken, testUser);

        assertThat(isValid).isFalse();
    }

    @Test
    void validateToken_malformedToken_returnsFalse() {
        UserDetails testUser = createUserDetails("test@example.com");
        String malformedToken = "invalid.token.string";
        when(tokenBlacklist.isTokenBlacklisted(anyString())).thenReturn(false);

        boolean isValid = jwtUtil.validateToken(malformedToken, testUser);

        assertThat(isValid).isFalse();
    }

    @Test
    void generateRefreshToken_success() {
        UserDetails testUser = createUserDetails("test@example.com");
        
        String token = jwtUtil.generateRefreshToken(testUser);

        assertThat(token).isNotNull();
        assertThat(token).isNotBlank();
        String extractedUsername = jwtUtil.extractUsername(token);
        assertThat(extractedUsername).isEqualTo("test@example.com");
    }

    @Test
    void validateRefreshToken_validToken_returnsTrue() {
        boolean isValid = jwtUtil.validateRefreshToken(refreshToken);

        assertThat(isValid).isTrue();
    }

    @Test
    void validateRefreshToken_expiredToken_returnsFalse() {
        String expiredRefreshToken = Jwts.builder()
                .setClaims(Map.of("tokenType", "refresh"))
                .setSubject("test@example.com")
                .setIssuedAt(new Date(System.currentTimeMillis() - 1000 * 60 * 60 * 24 * 8))
                .setExpiration(new Date(System.currentTimeMillis() - 1000 * 60 * 60 * 24))
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .compact();

        boolean isValid = jwtUtil.validateRefreshToken(expiredRefreshToken);

        assertThat(isValid).isFalse();
    }

    @Test
    void isRefreshToken_returnsTrue_forRefreshToken() {
        boolean isRefresh = jwtUtil.isRefreshToken(refreshToken);

        assertThat(isRefresh).isTrue();
    }

    @Test
    void isRefreshToken_returnsFalse_forRegularToken() {
        boolean isRefresh = jwtUtil.isRefreshToken(validToken);

        assertThat(isRefresh).isFalse();
    }

    @Test
    void isRefreshToken_returnsFalse_forInvalidToken() {
        String invalidToken = "invalid.token.here";

        boolean isRefresh = jwtUtil.isRefreshToken(invalidToken);

        assertThat(isRefresh).isFalse();
    }
}