package org.cloudfoundry.identity.uaa.util.beans;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Utility class for secure string comparisons that resist timing attacks.
 */
public final class SecureStringComparison {

    private SecureStringComparison() {
        // Utility class - prevent instantiation
    }

    /**
     * Performs constant-time string comparison to prevent timing attacks.
     * Uses MessageDigest.isEqual() which is designed for secure comparisons.
     * 
     * @param a first string to compare
     * @param b second string to compare
     * @return true if strings are equal, false otherwise
     */
    public static boolean constantTimeEquals(String a, String b) {
        if (a == null && b == null) {
            return true;
        }
        if (a == null || b == null) {
            return false;
        }
        
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
        
        return MessageDigest.isEqual(aBytes, bBytes);
    }
}