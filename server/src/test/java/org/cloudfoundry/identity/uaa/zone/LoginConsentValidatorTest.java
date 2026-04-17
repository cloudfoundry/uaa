package org.cloudfoundry.identity.uaa.zone;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class LoginConsentValidatorTest {

    @Test
    void testValidateNull() {
        List<String> errors = LoginConsentValidator.validate(null);
        assertThat(errors).isEmpty();
    }

    @Test
    void testValidateDisabled() {
        LoginConsent consent = new LoginConsent();
        consent.setEnabled(false);
        
        List<String> errors = LoginConsentValidator.validate(consent);
        assertThat(errors).isEmpty();
    }

    @Test
    void testValidateEnabledWithAllFields() {
        LoginConsent consent = new LoginConsent(
            true,
            "Notice",
            "You are accessing a system that is provided for authorized use only.",
            "I Accept",
            "Decline",
            "https://www.cloudfoundry.org",
            "12h"
        );
        
        List<String> errors = LoginConsentValidator.validate(consent);
        assertThat(errors).isEmpty();
    }

    @Test
    void testValidateEnabledWithoutDeclineLink() {
        LoginConsent consent = new LoginConsent(
            true,
            "Notice",
            "You are accessing a system that is provided for authorized use only.",
            "I Accept",
            "Decline",
            null,
            "12h"
        );
        
        List<String> errors = LoginConsentValidator.validate(consent);
        assertThat(errors).isEmpty();
    }

    @Test
    void testValidateEnabledMissingTitle() {
        LoginConsent consent = new LoginConsent(
            true,
            null,
            "You are accessing a system that is provided for authorized use only.",
            "I Accept",
            "Decline",
            "https://www.cloudfoundry.org",
            "12h"
        );
        
        List<String> errors = LoginConsentValidator.validate(consent);
        assertThat(errors).hasSize(1);
        assertThat(errors.getFirst()).contains("title is required");
    }

    @Test
    void testValidateEnabledEmptyTitle() {
        LoginConsent consent = new LoginConsent(
            true,
            "   ",
            "You are accessing a system that is provided for authorized use only.",
            "I Accept",
            "Decline",
            "https://www.cloudfoundry.org",
            "12h"
        );
        
        List<String> errors = LoginConsentValidator.validate(consent);
        assertThat(errors).hasSize(1);
        assertThat(errors.getFirst()).contains("title is required");
    }

    @Test
    void testValidateEnabledMissingText() {
        LoginConsent consent = new LoginConsent(
            true,
            "Notice",
            null,
            "I Accept",
            "Decline",
            "https://www.cloudfoundry.org",
            "12h"
        );
        
        List<String> errors = LoginConsentValidator.validate(consent);
        assertThat(errors).hasSize(1);
        assertThat(errors.getFirst()).contains("text is required");
    }

    @Test
    void testValidateEnabledMissingAcceptButtonText() {
        LoginConsent consent = new LoginConsent(
            true,
            "Notice",
            "You are accessing a system that is provided for authorized use only.",
            null,
            "Decline",
            "https://www.cloudfoundry.org",
            "12h"
        );
        
        List<String> errors = LoginConsentValidator.validate(consent);
        assertThat(errors).hasSize(1);
        assertThat(errors.getFirst()).contains("acceptButtonText is required");
    }

    @Test
    void testValidateEnabledMissingDeclineButtonText() {
        LoginConsent consent = new LoginConsent(
            true,
            "Notice",
            "You are accessing a system that is provided for authorized use only.",
            "I Accept",
            null,
            "https://www.cloudfoundry.org",
            "12h"
        );
        
        List<String> errors = LoginConsentValidator.validate(consent);
        assertThat(errors).hasSize(1);
        assertThat(errors.getFirst()).contains("declineButtonText is required");
    }

    @Test
    void testValidateEnabledMultipleErrors() {
        LoginConsent consent = new LoginConsent(
            true,
            null,
            null,
            null,
            null,
            "invalid-url",
            "invalid-duration"
        );
        
        List<String> errors = LoginConsentValidator.validate(consent);
        assertThat(errors).hasSize(6);
    }

    @Test
    void testValidateInvalidDeclineLink() {
        LoginConsent consent = new LoginConsent(
            true,
            "Notice",
            "You are accessing a system that is provided for authorized use only.",
            "I Accept",
            "Decline",
            "not-a-url",
            "12h"
        );
        
        List<String> errors = LoginConsentValidator.validate(consent);
        assertThat(errors).hasSize(1);
        assertThat(errors.getFirst()).contains("must be a valid URL");
    }

    @Test
    void testValidateValidHttpsUrl() {
        LoginConsent consent = new LoginConsent(
            true,
            "Notice",
            "Text",
            "Accept",
            "Decline",
            "https://example.com/path",
            "12h"
        );
        
        List<String> errors = LoginConsentValidator.validate(consent);
        assertThat(errors).isEmpty();
    }

    @Test
    void testValidateValidHttpUrl() {
        //noinspection HttpUrlsUsage
        LoginConsent consent = new LoginConsent(
            true,
            "Notice",
            "Text",
            "Accept",
            "Decline",
            "http://example.com",
            "12h"
        );
        
        List<String> errors = LoginConsentValidator.validate(consent);
        assertThat(errors).isEmpty();
    }

    @Test
    void testValidateInvalidUrlProtocol() {
        LoginConsent consent = new LoginConsent(
            true,
            "Notice",
            "Text",
            "Accept",
            "Decline",
            "ftp://example.com",
            "12h"
        );
        
        List<String> errors = LoginConsentValidator.validate(consent);
        assertThat(errors).hasSize(1);
        assertThat(errors.getFirst()).contains("must be a valid URL");
    }

    @Test
    void testValidateValidDurations() {
        String[] validDurations = {"0", "12h", "7d", "1w", "1m", "24H", "30D"};
        
        for (String duration : validDurations) {
            LoginConsent consent = new LoginConsent(
                true,
                "Title",
                "Text",
                "Accept",
                "Decline",
                null,
                duration
            );
            
            List<String> errors = LoginConsentValidator.validate(consent);
            assertThat(errors).as("Duration " + duration + " should be valid").isEmpty();
        }
    }

    @Test
    void testValidateInvalidDurations() {
        String[] invalidDurations = {"invalid", "12x", "abc", "-1h", "0h"};
        
        for (String duration : invalidDurations) {
            LoginConsent consent = new LoginConsent(
                true,
                "Title",
                "Text",
                "Accept",
                "Decline",
                null,
                duration
            );
            
            List<String> errors = LoginConsentValidator.validate(consent);
            assertThat(errors).as("Duration " + duration + " should be invalid").isNotEmpty();
            assertThat(errors.stream().anyMatch(e -> e.contains("consentValidDuration"))).isTrue();
        }
    }

    @Test
    void testValidateWithoutDuration() {
        LoginConsent consent = new LoginConsent(
            true,
            "Title",
            "Text",
            "Accept",
            "Decline",
            null,
            null
        );
        
        List<String> errors = LoginConsentValidator.validate(consent);
        assertThat(errors).isEmpty(); // Duration is optional, defaults to 24h
    }
}
