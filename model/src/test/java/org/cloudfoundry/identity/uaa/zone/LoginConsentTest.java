package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@Disabled
class LoginConsentTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void testDefaultConstructor() {
        LoginConsent consent = new LoginConsent();
        assertThat(consent.isEnabled()).isFalse();
        assertThat(consent.getTitle()).isNotNull();
        assertThat(consent.getText()).isNull();
        assertThat(consent.getAcceptButtonText()).isNotNull();
        assertThat(consent.getDeclineLink()).isNull();
        assertThat(consent.getConsentValidDuration()).isNotNull();
    }

    @Test
    void testFullConstructor() {
        LoginConsent consent = new LoginConsent(
            true,
            "Test Title",
            "Test Text",
            "Accept",
            "https://example.com",
            "12h"
        );

        assertThat(consent.isEnabled()).isTrue();
        assertThat(consent.getTitle()).isEqualTo("Test Title");
        assertThat(consent.getText()).isEqualTo("Test Text");
        assertThat(consent.getAcceptButtonText()).isEqualTo("Accept");
        assertThat(consent.getDeclineLink()).isEqualTo("https://example.com");
        assertThat(consent.getConsentValidDuration()).isEqualTo("12h");
    }

    @Test
    void testSettersAndGetters() {
        LoginConsent consent = new LoginConsent();
        
        consent.setEnabled(true);
        consent.setTitle("Notice");
        consent.setText("You are accessing a system for authorized use only");
        consent.setAcceptButtonText("I Accept");
        consent.setDeclineLink("https://www.cloudfoundry.org");
        consent.setConsentValidDuration("24h");

        assertThat(consent.isEnabled()).isTrue();
        assertThat(consent.getTitle()).isEqualTo("Notice");
        assertThat(consent.getText()).isEqualTo("You are accessing a system for authorized use only");
        assertThat(consent.getAcceptButtonText()).isEqualTo("I Accept");
        assertThat(consent.getDeclineLink()).isEqualTo("https://www.cloudfoundry.org");
        assertThat(consent.getConsentValidDuration()).isEqualTo("24h");
    }

    @Test
    void testJsonSerialization() throws Exception {
        LoginConsent consent = new LoginConsent(
                true,
                "Test Title",
                "Test Text",
                "Accept",
                "https://example.com",
                "12h"
        );

        String json = objectMapper.writeValueAsString(consent);
        assertThat(json).isNotNull()
                .contains("\"enabled\":true")
                .contains("\"title\":\"Test Title\"")
                .contains("\"text\":\"Test Text\"");
    }

    @Test
    void testJsonDeserialization() throws Exception {
        String json = """
            {
                "enabled": true,
                "title": "Test Title",
                "text": "Test Text",
                "acceptButtonText": "Accept",
                "declineLink": "https://example.com",
                "consentValidDuration": "12h"
            }
            """;

        LoginConsent consent = objectMapper.readValue(json, LoginConsent.class);
        
        assertThat(consent.isEnabled()).isTrue();
        assertThat(consent.getTitle()).isEqualTo("Test Title");
        assertThat(consent.getText()).isEqualTo("Test Text");
        assertThat(consent.getAcceptButtonText()).isEqualTo("Accept");
        assertThat(consent.getDeclineLink()).isEqualTo("https://example.com");
        assertThat(consent.getConsentValidDuration()).isEqualTo("12h");
    }

    @Test
    void testJsonSerializationWithNulls() throws Exception {
        LoginConsent consent = new LoginConsent();
        consent.setEnabled(true);
        consent.setTitle("Title");
        consent.setText("Text");

        String json = objectMapper.writeValueAsString(consent);
        assertThat(json).isNotNull()
                // Non-null fields should be included
                .contains("\"enabled\":true")
                .contains("\"title\":\"Title\"")
                // Null fields should not be included (JsonInclude.Include.NON_NULL)
                .doesNotContain("\"declineLink\"");
    }

    @Test
    void testEquals() {
        LoginConsent consent1 = new LoginConsent(true, "Title", "Text", "Accept", "https://example.com", "12h");
        LoginConsent consent2 = new LoginConsent(true, "Title", "Text", "Accept", "https://example.com", "12h");
        LoginConsent consent3 = new LoginConsent(true, "Different", "Text", "Accept", "https://example.com", "12h");

        assertThat(consent1).isNotNull()
                .isEqualTo(consent2)
                .isNotEqualTo(consent3)
                .isNotEqualTo(new Object());
    }

    @Test
    void testHashCode() {
        LoginConsent consent1 = new LoginConsent(true, "Title", "Text", "Accept", "https://example.com", "12h");
        LoginConsent consent2 = new LoginConsent(true, "Title", "Text", "Accept", "https://example.com", "12h");

        assertThat(consent2).hasSameHashCodeAs(consent1);
    }

    @Test
    void testToString() {
        LoginConsent consent = new LoginConsent(true, "Title", "Test Text", "Accept", "https://example.com", "12h");
        String toString = consent.toString();

        assertThat(toString).isNotNull()
                .contains("enabled=true")
                .contains("title=Title")
                .contains("acceptButtonText=Accept");
    }
}
