package org.cloudfoundry.identity.uaa.zone;

import org.springframework.util.StringUtils;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * Validator for LoginConsent configuration.
 */
public class LoginConsentValidator {

    private LoginConsentValidator() {
        // Utility class
    }

    /**
     * Validate the LoginConsent configuration.
     *
     * @param loginConsent the consent configuration to validate
     * @return list of validation error messages (empty if valid)
     */
    public static List<String> validate(LoginConsent loginConsent) {
        List<String> errors = new ArrayList<>();

        if (loginConsent == null) {
            return errors; // null is valid (feature disabled)
        }

        if (!loginConsent.isEnabled()) {
            return errors; // If disabled, no validation needed
        }

        // When enabled, validate required fields
        if (!StringUtils.hasText(loginConsent.getTitle())) {
            errors.add("loginConsent.title is required when loginConsent is enabled");
        }

        if (!StringUtils.hasText(loginConsent.getText())) {
            errors.add("loginConsent.text is required when loginConsent is enabled");
        }

        if (!StringUtils.hasText(loginConsent.getAcceptButtonText())) {
            errors.add("loginConsent.acceptButtonText is required when loginConsent is enabled");
        }

        // Validate declineLink if provided
        if (StringUtils.hasText(loginConsent.getDeclineLink())) {
            if (!isValidUrl(loginConsent.getDeclineLink())) {
                errors.add("loginConsent.declineLink must be a valid URL");
            }
        }

        // Validate consentValidDuration format if provided
        if (StringUtils.hasText(loginConsent.getConsentValidDuration())) {
            if (!isValidDuration(loginConsent.getConsentValidDuration())) {
                errors.add("loginConsent.consentValidDuration must be in format: 0, 12h, 7d, 1w, or 1m");
            }
        }

        return errors;
    }

    /**
     * Check if a string is a valid URL.
     *
     * @param urlString the URL string to validate
     * @return true if valid URL, false otherwise
     */
    private static boolean isValidUrl(String urlString) {
        try {
            URL url = new URI(urlString).toURL();
            String protocol = url.getProtocol();
            return "http".equalsIgnoreCase(protocol) || "https".equalsIgnoreCase(protocol);
        } catch (IllegalArgumentException | MalformedURLException | URISyntaxException e) {
            return false;
        }
    }

    /**
     * Check if a duration string is in valid format.
     * Valid formats: 0, 12h, 7d, 1w, 1m
     *
     * @param duration the duration string
     * @return true if a valid format, false otherwise
     */
    private static boolean isValidDuration(String duration) {
        if (!StringUtils.hasText(duration)) {
            return false;
        }

        duration = duration.trim();

        // Special case: 0 is valid
        if ("0".equals(duration)) {
            return true;
        }

        // Check format: number followed by h, d, w, or m
        if (duration.length() < 2) {
            return false;
        }

        String numberPart = duration.substring(0, duration.length() - 1);
        String unit = duration.substring(duration.length() - 1);

        try {
            long value = Long.parseLong(numberPart);
            if (value <= 0) {
                return false;
            }
            return "h".equalsIgnoreCase(unit) || 
                   "d".equalsIgnoreCase(unit) || 
                   "w".equalsIgnoreCase(unit) || 
                   "m".equalsIgnoreCase(unit);
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
