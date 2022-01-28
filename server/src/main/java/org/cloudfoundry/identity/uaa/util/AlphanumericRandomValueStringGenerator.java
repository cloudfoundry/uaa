package org.cloudfoundry.identity.uaa.util;

public class AlphanumericRandomValueStringGenerator
        extends org.springframework.security.oauth2.common.util.RandomValueStringGenerator {
    private static final char[] DEFAULT_CODEC =
            "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            .toCharArray();

    public AlphanumericRandomValueStringGenerator() {
        super();
    }

    public AlphanumericRandomValueStringGenerator(int length) {
        super(length);
    }

    /**
     * Convert these random bytes to a verifier string. The length of the byte array can be
     * {@link #setLength(int) configured}. The default implementation mods the bytes to fit into the
     * ASCII letters 1-9, A-Z, a-z.
     *
     * @param verifierBytes The bytes.
     * @return The string.
     */
    @Override
    protected String getAuthorizationCodeString(byte[] verifierBytes) {
        char[] chars = new char[verifierBytes.length];
        for (int i = 0; i < verifierBytes.length; i++) {
            chars[i] = DEFAULT_CODEC[((verifierBytes[i] & 0xFF) % DEFAULT_CODEC.length)];
        }
        return new String(chars);
    }
}
