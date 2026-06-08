package org.cloudfoundry.identity.uaa.zone;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class LoginConsentValidatorTest {

    @Test
    void validateNull() {
        List<String> errors = LoginConsentValidator.validate(null);
        assertThat(errors).isEmpty();
    }

    @Test
    void validateDisabled() {
        LoginConsent consent = new LoginConsent();
        consent.setEnabled(false);
        
        List<String> errors = LoginConsentValidator.validate(consent);
        assertThat(errors).isEmpty();
    }

    @Test
    void validateEnabledWithAllFields() {
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
    void validateEnabledWithoutDeclineLink() {
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
    void validateEnabledMissingTitle() {
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
        assertThat(errors).hasSize(1)
                .contains("loginConsent.title is required when loginConsent is enabled");
    }

    @Test
    void validateEnabledEmptyTitle() {
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
        assertThat(errors).hasSize(1)
                .contains("loginConsent.title is required when loginConsent is enabled");
    }

    @Test
    void validateEnabledMissingText() {
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
        assertThat(errors).hasSize(1)
                .contains("loginConsent.text is required when loginConsent is enabled");
    }

    @Test
    void validateEnabledMissingAcceptButtonText() {
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
        assertThat(errors).hasSize(1)
                .contains("loginConsent.acceptButtonText is required when loginConsent is enabled");
    }

    @Test
    void validateEnabledMissingDeclineButtonText() {
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
        assertThat(errors).hasSize(1)
                .contains("loginConsent.declineButtonText is required when loginConsent is enabled");
    }

    @Test
    void validateEnabledMultipleErrors() {
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
    void validateInvalidDeclineLink() {
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
        assertThat(errors).hasSize(1)
                .contains("loginConsent.declineLink must be a valid URL");
    }

    @Test
    void validateValidHttpsUrl() {
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
    void validateValidHttpUrl() {
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
    void validateInvalidUrlProtocol() {
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
        assertThat(errors).hasSize(1)
                .contains("loginConsent.declineLink must be a valid URL");
    }

    @Test
    void validateValidDurations() {
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
    void validateInvalidDurations() {
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
    void validateWithoutDuration() {
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
