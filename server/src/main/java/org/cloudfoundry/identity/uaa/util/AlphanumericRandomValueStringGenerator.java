package org.cloudfoundry.identity.uaa.util;

import java.security.SecureRandom;
import java.util.Random;

public class AlphanumericRandomValueStringGenerator {
    private static final char[] DEFAULT_CODEC =
            "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            .toCharArray();

    private Random random = new SecureRandom();

    private int length;

    public AlphanumericRandomValueStringGenerator() {
        this(6);
    }

    public AlphanumericRandomValueStringGenerator(int length) {
        this.length = length;
    }

    public String generate() {
        byte[] verifierBytes = new byte[length];
        random.nextBytes(verifierBytes);
        return getAuthorizationCodeString(verifierBytes);
    }

    /**
     * Convert these random bytes to a verifier string. The length of the byte array can be
     * {@link #setLength(int) configured}. The default implementation mods the bytes to fit into the
     * ASCII letters 1-9, A-Z, a-z.
     *
     * @param verifierBytes The bytes.
     * @return The string.
     */
    protected String getAuthorizationCodeString(byte[] verifierBytes) {
        char[] chars = new char[verifierBytes.length];
        for (int i = 0; i < verifierBytes.length; i++) {
            chars[i] = DEFAULT_CODEC[((verifierBytes[i] & 0xFF) % DEFAULT_CODEC.length)];
        }
        return new String(chars);
    }

    /**
     * The random value generator used to create token secrets.
     *
     * @param random The random value generator used to create token secrets.
     */
    public void setRandom(Random random) {
        this.random = random;
    }

    /**
     * The length of string to generate.  A length less than or equal to 0 will result in an {@code IllegalArgumentException}.
     *
     * @param length the length to set
     */
    public void setLength(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("length must be greater than 0");
        }
        this.length = length;
    }
}
