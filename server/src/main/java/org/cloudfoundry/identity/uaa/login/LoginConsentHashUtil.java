package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.zone.LoginConsent;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Utility class for calculating consent hashes used to track consent versioning.
 * The hash is calculated from the consent title and text to detect changes.
 * Previously calculated hashes are cached to avoid recomputation.
 */
public class LoginConsentHashUtil {

    private static final int DEFAULT_SESSION_DURATION = 24 * 60 * 60; // 24 hours in seconds
    private static final ConcurrentHashMap<String, String> consentHashCache = new ConcurrentHashMap<>();

    private LoginConsentHashUtil() {
        // Utility class
    }

    /**
     * Calculate a SHA-256 hash of the consent content (title + text).
     * This hash is used to detect when consent text has changed and requires re-acceptance.
     *
     * @param consent the LoginConsent configuration
     * @return SHA-256 hash as a hexadecimal string, or null if consent is null or disabled
     */
    public static String calculateConsentHash(LoginConsent consent) {
        if (consent == null || !consent.isEnabled()) {
            return null;
        }

        String title = StringUtils.hasText(consent.getTitle()) ? consent.getTitle() : "";
        String text = StringUtils.hasText(consent.getText()) ? consent.getText() : "";
        
        // Format: <title_length>:<title>|<text_length>:<text>
        String content = title.length() + ":" + title + "|" + text.length() + ":" + text;

        return consentHashCache.computeIfAbsent(content, c -> {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(c.getBytes(StandardCharsets.UTF_8));
                return bytesToHex(hash);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("SHA-256 algorithm not available", e);
            }
        });
    }

    /**
     * Convert byte array to hexadecimal string.
     *
     * @param bytes the byte array
     * @return hexadecimal string representation
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /**
     * Parse the consent valid duration string into seconds.
     * Supports formats: 0, 15m, 12h, 7d, 1w, 1y
     *
     * @param duration the duration string (e.g., "12h", "7d", "0")
     * @return duration in seconds; returns 0 only if duration is "0", otherwise defaults
     *         to 24 hours (in seconds) for missing or invalid values
     */
    public static long parseDurationToSeconds(String duration) {
        if (!StringUtils.hasText(duration)) {
            return DEFAULT_SESSION_DURATION;
        }

        duration = duration.trim();

        // Special case: 0 means always prompt
        if ("0".equals(duration)) {
            return 0;
        }

        try {
            // Extract number and unit
            int length = duration.length();
            if (length < 2) {
                return DEFAULT_SESSION_DURATION; // Default if invalid
            }

            String numberPart = duration.substring(0, length - 1);
            String unit = duration.substring(length - 1);

            long value = Long.parseLong(numberPart);

            return switch (unit.toLowerCase()) {
                case "m" -> value * 60;                // minutes
                case "h" -> value * 60 * 60;           // hours
                case "d" -> value * 24 * 60 * 60;      // days
                case "w" -> value * 7 * 24 * 60 * 60;  // weeks (7 days)
                case "y" -> value * 365 * 24 * 60 * 60; // years (365 days)
                default -> DEFAULT_SESSION_DURATION;
            };
        } catch (NumberFormatException e) {
            return DEFAULT_SESSION_DURATION; // Default: if not parsable
        }
    }
}
