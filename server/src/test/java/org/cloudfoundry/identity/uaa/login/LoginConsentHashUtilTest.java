package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.zone.LoginConsent;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LoginConsentHashUtilTest {

    @Test
    void calculateConsentHash() {
        LoginConsent consent = new LoginConsent(true, "Title", "Text", "Accept", "Decline", null, "12h");
        String hash = LoginConsentHashUtil.calculateConsentHash(consent);

        assertThat(hash).hasSize(64); // SHA-256 produces 64 hex characters
    }

    @Test
    void calculateConsentHashConsistency() {
        LoginConsent consent1 = new LoginConsent(true, "Title", "Text", "Accept", "Decline", null, "12h");
        LoginConsent consent2 = new LoginConsent(true, "Title", "Text", "Accept", "Decline", null, "24h");
        
        String hash1 = LoginConsentHashUtil.calculateConsentHash(consent1);
        String hash2 = LoginConsentHashUtil.calculateConsentHash(consent2);
        
        // Same title and text should produce same hash
        assertThat(hash2).isEqualTo(hash1);
    }

    @Test
    void calculateConsentHashChangesWithTitle() {
        LoginConsent consent1 = new LoginConsent(true, "Title1", "Text", "Accept", "Decline", null, "12h");
        LoginConsent consent2 = new LoginConsent(true, "Title2", "Text", "Accept", "Decline", null, "12h");
        
        String hash1 = LoginConsentHashUtil.calculateConsentHash(consent1);
        String hash2 = LoginConsentHashUtil.calculateConsentHash(consent2);
        
        // Different titles should produce different hashes
        assertThat(hash2).isNotEqualTo(hash1);
    }

    @Test
    void calculateConsentHashChangesWithText() {
        LoginConsent consent1 = new LoginConsent(true, "Title", "Text1", "Accept", "Decline", null, "12h");
        LoginConsent consent2 = new LoginConsent(true, "Title", "Text2", "Accept", "Decline", null, "12h");
        
        String hash1 = LoginConsentHashUtil.calculateConsentHash(consent1);
        String hash2 = LoginConsentHashUtil.calculateConsentHash(consent2);
        
        // Different text should produce different hashes
        assertThat(hash2).isNotEqualTo(hash1);
    }

    @Test
    void calculateConsentHashWithNullConsent() {
        String hash = LoginConsentHashUtil.calculateConsentHash(null);
        assertThat(hash).isNull();
    }

    @Test
    void calculateConsentHashWithDisabledConsent() {
        LoginConsent consent = new LoginConsent(false, "Title", "Text", "Accept", "Decline", null, "12h");
        String hash = LoginConsentHashUtil.calculateConsentHash(consent);
        assertThat(hash).isNull();
    }

    @Test
    void calculateConsentHashWithEmptyFields() {
        LoginConsent consent = new LoginConsent(true, "", "", "Accept", "Decline", null, "12h");
        String hash = LoginConsentHashUtil.calculateConsentHash(consent);

        assertThat(hash)
                .hasSize(64);
    }

    @Test
    void parseDurationToSecondsMinutes() {
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("1m")).isEqualTo(60);
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("3m")).isEqualTo(3 * 60);
    }

    @Test
    void parseDurationToSecondsHours() {
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("12h")).isEqualTo(12 * 60 * 60);
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("1h")).isEqualTo(60 * 60);
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("24h")).isEqualTo(24 * 60 * 60);
    }

    @Test
    void parseDurationToSecondsDays() {
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("7d")).isEqualTo(7 * 24 * 60 * 60);
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("1d")).isEqualTo(24 * 60 * 60);
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("30d")).isEqualTo(30 * 24 * 60 * 60);
    }

    @Test
    void parseDurationToSecondsWeeks() {
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("1w")).isEqualTo(7 * 24 * 60 * 60);
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("2w")).isEqualTo(2 * 7 * 24 * 60 * 60);
    }

    @Test
    void parseDurationToSecondsYears() {
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("1y")).isEqualTo(365 * 24 * 60 * 60);
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("2y")).isEqualTo(2 * 365 * 24 * 60 * 60);
    }

    @Test
    void parseDurationToSecondsZero() {
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("0")).isZero();
    }

    @Test
    void parseDurationToSecondsNull() {
        // Should return default: 24 hours
        assertThat(LoginConsentHashUtil.parseDurationToSeconds(null)).isEqualTo(24 * 60 * 60);
    }

    @Test
    void parseDurationToSecondsEmpty() {
        // Should return default: 24 hours
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("")).isEqualTo(24 * 60 * 60);
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("   ")).isEqualTo(24 * 60 * 60);
    }

    @Test
    void parseDurationToSecondsInvalid() {
        // Invalid formats should return default: 24 hours
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("invalid")).isEqualTo(24 * 60 * 60);
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("12x")).isEqualTo(24 * 60 * 60);
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("abc")).isEqualTo(24 * 60 * 60);
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("12")).isEqualTo(24 * 60 * 60);
    }

    @Test
    void parseDurationToSecondsCaseInsensitive() {
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("1M")).isEqualTo(60);
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("12H")).isEqualTo(12 * 60 * 60);
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("7D")).isEqualTo(7 * 24 * 60 * 60);
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("1W")).isEqualTo(7 * 24 * 60 * 60);
        assertThat(LoginConsentHashUtil.parseDurationToSeconds("1Y")).isEqualTo(365 * 24 * 60 * 60);
    }

    @Test
    void hashCollision() {
        // Case 1: title contains pipe, short text
        LoginConsent consent1 = new LoginConsent(true, "abc|def", "ghi", "Accept", "Decline", null, "12h");
        
        // Case 2: short title, text contains pipe  
        LoginConsent consent2 = new LoginConsent(true, "abc", "def|ghi", "Accept", "Decline", null, "12h");
        
        String hash1 = LoginConsentHashUtil.calculateConsentHash(consent1);
        String hash2 = LoginConsentHashUtil.calculateConsentHash(consent2);

        assertThat(hash1).as("Different title/text combinations should produce different hashes")
                          .isNotEqualTo(hash2);
    }
}
