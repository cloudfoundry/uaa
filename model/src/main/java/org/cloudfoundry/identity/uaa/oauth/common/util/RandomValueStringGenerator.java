package org.cloudfoundry.identity.uaa.oauth.common.util;

import java.security.SecureRandom;
import java.util.Random;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 utils
 */
public class RandomValueStringGenerator {

    private static final char[] DEFAULT_CODEC = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_"
            .toCharArray();

    private final char[] defaultCodec;
    private Random random = new SecureRandom();

    private int length;

    /**
     * Create a generator with the default length (6).
     */
    public RandomValueStringGenerator() {
        this(6);
    }

    protected RandomValueStringGenerator(char[] codec) {
        this(codec, 6);
    }

    /**
     * Create a generator of random strings of the length provided
     * 
     * @param length the length of the strings generated
     */
    public RandomValueStringGenerator(int length) {
        defaultCodec = DEFAULT_CODEC;
        this.length = length;
    }

    protected RandomValueStringGenerator(char[] codec, int length) {
        defaultCodec = codec;
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
     * ASCII letters 1-9, A-Z, a-z, -_ .
     * 
     * @param verifierBytes The bytes.
     * @return The string.
     */
    protected String getAuthorizationCodeString(byte[] verifierBytes) {
        char[] chars = new char[verifierBytes.length];
        for (int i = 0; i < verifierBytes.length; i++) {
            chars[i] = defaultCodec[((verifierBytes[i] & 0xFF) % defaultCodec.length)];
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
