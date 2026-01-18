package com.tailormade.auth.util;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class LoginAttemptTrackerTest {

    private LoginAttemptTracker tracker;

    @BeforeEach
    void setUp() {
        tracker = new LoginAttemptTracker();
    }

    @Test
    void recordFailedAttempt_firstAttempt_incrementsCounter() {
        tracker.recordFailedAttempt("test@example.com");

        assertThat(tracker.getRemainingAttempts("test@example.com")).isEqualTo(4);
        assertThat(tracker.isAccountLocked("test@example.com")).isFalse();
    }

    @Test
    void recordFailedAttempt_multipleAttempts_incrementsCorrectly() {
        tracker.recordFailedAttempt("test@example.com");
        tracker.recordFailedAttempt("test@example.com");
        tracker.recordFailedAttempt("test@example.com");

        assertThat(tracker.getRemainingAttempts("test@example.com")).isEqualTo(2);
        assertThat(tracker.isAccountLocked("test@example.com")).isFalse();
    }

    @Test
    void recordFailedAttempt_reachesMaxAttempts_locksAccount() {
        for (int i = 0; i < 5; i++) {
            tracker.recordFailedAttempt("test@example.com");
        }

        assertThat(tracker.isAccountLocked("test@example.com")).isTrue();
        assertThat(tracker.getRemainingAttempts("test@example.com")).isEqualTo(0);
    }

    @Test
    void recordFailedAttempt_beyondMaxAttempts_keepsLocked() {
        for (int i = 0; i < 5; i++) {
            tracker.recordFailedAttempt("test@example.com");
        }

        tracker.recordFailedAttempt("test@example.com");

        assertThat(tracker.isAccountLocked("test@example.com")).isTrue();
        assertThat(tracker.getRemainingAttempts("test@example.com")).isEqualTo(0);
    }

    @Test
    void recordSuccessfulAttempt_resetsAttempts() {
        tracker.recordFailedAttempt("test@example.com");
        tracker.recordFailedAttempt("test@example.com");

        tracker.recordSuccessfulAttempt("test@example.com");

        assertThat(tracker.getRemainingAttempts("test@example.com")).isEqualTo(5);
        assertThat(tracker.isAccountLocked("test@example.com")).isFalse();
    }

    @Test
    void recordSuccessfulAttempt_nonExistentUser_noError() {
        assertThatNoException().isThrownBy(() -> 
            tracker.recordSuccessfulAttempt("nonexistent@example.com")
        );
    }

    @Test
    void isAccountLocked_nonExistentUser_returnsFalse() {
        // When
        boolean locked = tracker.isAccountLocked("nonexistent@example.com");

        // Then
        assertThat(locked).isFalse();
    }

    @Test
    void isAccountLocked_belowMaxAttempts_returnsFalse() {
        // Given
        tracker.recordFailedAttempt("test@example.com");
        tracker.recordFailedAttempt("test@example.com");

        // When
        boolean locked = tracker.isAccountLocked("test@example.com");

        // Then
        assertThat(locked).isFalse();
    }

    @Test
    void getLockoutMessage_lockedAccount_returnsProperMessage() {
        // Given - lock the account
        for (int i = 0; i < 5; i++) {
            tracker.recordFailedAttempt("test@example.com");
        }

        // When
        String message = tracker.getLockoutMessage("test@example.com");

        // Then
        assertThat(message).contains("Account is locked");
        assertThat(message).contains("minutes");
    }

    @Test
    void getLockoutMessage_nonLockedAccount_returnsGenericMessage() {
        // When
        String message = tracker.getLockoutMessage("test@example.com");

        // Then
        assertThat(message).isEqualTo("Account is temporarily locked due to multiple failed login attempts");
    }

    @Test
    void getRemainingAttempts_nonExistentUser_returnsMaxAttempts() {
        // When
        int remaining = tracker.getRemainingAttempts("newuser@example.com");

        // Then
        assertThat(remaining).isEqualTo(5);
    }

    @Test
    void getRemainingAttempts_negativeAttempts_returnsZero() {
        for (int i = 0; i < 5; i++) {
            tracker.recordFailedAttempt("test@example.com");
        }
        
        tracker.recordFailedAttempt("test@example.com");

        int remaining = tracker.getRemainingAttempts("test@example.com");

        assertThat(remaining).isEqualTo(0);
    }

    @Test
    void cleanupExpiredEntries_removesExpiredLockouts() {
        for (int i = 0; i < 5; i++) {
            tracker.recordFailedAttempt("test@example.com");
        }
        assertThat(tracker.isAccountLocked("test@example.com")).isTrue();

        assertThatNoException().isThrownBy(() -> 
            tracker.cleanupExpiredEntries()
        );
    }

    @Test
    void multipleUsers_trackingWorksIndependently() {
        String user1 = "user1@example.com";
        String user2 = "user2@example.com";

        tracker.recordFailedAttempt(user1);
        tracker.recordFailedAttempt(user1);
        tracker.recordFailedAttempt(user2);

        assertThat(tracker.getRemainingAttempts(user1)).isEqualTo(3);
        assertThat(tracker.getRemainingAttempts(user2)).isEqualTo(4);
        assertThat(tracker.isAccountLocked(user1)).isFalse();
        assertThat(tracker.isAccountLocked(user2)).isFalse();
    }

    @Test
    void recordFailedAttempt_thenSuccessful_clearsLockout() {
        for (int i = 0; i < 5; i++) {
            tracker.recordFailedAttempt("test@example.com");
        }
        assertThat(tracker.isAccountLocked("test@example.com")).isTrue();

        tracker.recordSuccessfulAttempt("test@example.com");

        assertThat(tracker.isAccountLocked("test@example.com")).isFalse();
        assertThat(tracker.getRemainingAttempts("test@example.com")).isEqualTo(5);
    }
}