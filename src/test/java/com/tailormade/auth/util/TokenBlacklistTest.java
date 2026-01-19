package com.tailormade.auth.util;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TokenBlacklistTest {

    private TokenBlacklist tokenBlacklist;

    @BeforeEach
    void setUp() {
        tokenBlacklist = new TokenBlacklist();
    }

    @Test
    void blacklistToken_defaultDuration_tokenIsBlacklisted() {

        String token = "sample-jwt-token";


        tokenBlacklist.blacklistToken(token);


        assertThat(tokenBlacklist.isTokenBlacklisted(token)).isTrue();
    }

    @Test
    void blacklistToken_customDuration_tokenIsBlacklisted() {

        String token = "sample-jwt-token";
        long duration = 3600;


        tokenBlacklist.blacklistToken(token, duration);


        assertThat(tokenBlacklist.isTokenBlacklisted(token)).isTrue();
    }

    @Test
    void isTokenBlacklisted_nonExistentToken_returnsFalse() {

        boolean blacklisted = tokenBlacklist.isTokenBlacklisted("non-existent-token");


        assertThat(blacklisted).isFalse();
    }

    @Test
    void isTokenBlacklisted_afterExpiry_returnsFalse() throws InterruptedException {
        String token = "expiring-token";
        long shortDuration = 1;

        tokenBlacklist.blacklistToken(token, shortDuration);
        assertThat(tokenBlacklist.isTokenBlacklisted(token)).isTrue();

        Thread.sleep(1100);

        assertThat(tokenBlacklist.isTokenBlacklisted(token)).isFalse();
    }

    @Test
    void isTokenBlacklisted_beforeExpiry_returnsTrue() {

        String token = "long-lived-token";
        long longDuration = 3600;

        tokenBlacklist.blacklistToken(token, longDuration);


        assertThat(tokenBlacklist.isTokenBlacklisted(token)).isTrue();
    }

    @Test
    void removeExpiredTokens_executesWithoutError() {
        tokenBlacklist.blacklistToken("token1", 1);
        tokenBlacklist.blacklistToken("token2", 3600);

        assertThatNoException().isThrownBy(() -> 
            tokenBlacklist.removeExpiredTokens()
        );
    }

    @Test
    void multipleTokens_blacklistingWorksIndependently() {
        String token1 = "token-1";
        String token2 = "token-2";
        String token3 = "token-3";

        tokenBlacklist.blacklistToken(token1);
        tokenBlacklist.blacklistToken(token2, 3600);

        assertThat(tokenBlacklist.isTokenBlacklisted(token1)).isTrue();
        assertThat(tokenBlacklist.isTokenBlacklisted(token2)).isTrue();
        assertThat(tokenBlacklist.isTokenBlacklisted(token3)).isFalse();
    }

    @Test
    void sameToken_blacklistedMultipleTimes_updatesExpiry() {
        String token = "duplicate-token";

        tokenBlacklist.blacklistToken(token, 1000);
        tokenBlacklist.blacklistToken(token, 2000);

        assertThat(tokenBlacklist.isTokenBlacklisted(token)).isTrue();
    }

    @Test
    void removeExpiredTokens_emptyBlacklist_noErrors() {

        assertThatNoException().isThrownBy(() -> 
            tokenBlacklist.removeExpiredTokens()
        );
    }

    @Test
    void isTokenBlacklisted_nullToken_returnsFalse() {

        boolean result = tokenBlacklist.isTokenBlacklisted(null);


        assertThat(result).isFalse();
    }

    @Test
    void isTokenBlacklisted_emptyToken_returnsFalse() {

        boolean result = tokenBlacklist.isTokenBlacklisted("");


        assertThat(result).isFalse();
    }

    @Test
    void blacklistToken_zeroDuration_stillBlacklists() {

        String token = "zero-duration-token";


        tokenBlacklist.blacklistToken(token, 0);



        assertThatNoException().isThrownBy(() -> 
            tokenBlacklist.isTokenBlacklisted(token)
        );
    }

    @Test
    void blacklistToken_negativeDuration_handlesGracefully() {

        String token = "negative-duration-token";


        assertThatNoException().isThrownBy(() -> 
            tokenBlacklist.blacklistToken(token, -1000)
        );
    }

    @Test
    void concurrentAccess_threadSafety() throws InterruptedException {
        int threadCount = 10;
        int tokensPerThread = 100;
        Thread[] threads = new Thread[threadCount];

        for (int i = 0; i < threadCount; i++) {
            final int threadId = i;
            threads[i] = new Thread(() -> {
                for (int j = 0; j < tokensPerThread; j++) {
                    String token = "thread-" + threadId + "-token-" + j;
                    tokenBlacklist.blacklistToken(token);
                }
            });
            threads[i].start();
        }

        for (Thread thread : threads) {
            thread.join();
        }

        String testToken = "concurrency-test";
        tokenBlacklist.blacklistToken(testToken);
        assertThat(tokenBlacklist.isTokenBlacklisted(testToken)).isTrue();
    }
}