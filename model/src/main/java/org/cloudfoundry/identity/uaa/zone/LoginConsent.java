package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

/**
 * Configuration for the login consent modal that can be displayed on the login page.
 * This is separate from the OAuth approval consent feature.
 */
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class LoginConsent {
    private boolean enabled = false;
    private String title = "Terms and Conditions";
    private String text;
    private String acceptButtonText = "I Agree";
    private String declineButtonText = "Decline";
    private String declineLink;
    private String consentValidDuration = "1d";

    public LoginConsent() {
    }

    public LoginConsent(boolean enabled, String title, String text, String acceptButtonText, String declineButtonText, String declineLink, String consentValidDuration) {
        this.enabled = enabled;
        this.title = title;
        this.text = text;
        this.acceptButtonText = acceptButtonText;
        this.declineButtonText = declineButtonText;
        this.declineLink = declineLink;
        this.consentValidDuration = consentValidDuration;
    }
}
