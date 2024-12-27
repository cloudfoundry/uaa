package org.cloudfoundry.identity.uaa.util;

import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;

public class AlphanumericRandomValueStringGenerator extends RandomValueStringGenerator {
    private static final char[] DEFAULT_CODEC =
            "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    .toCharArray();

    public AlphanumericRandomValueStringGenerator() {
        super(DEFAULT_CODEC, 6);
    }

    public AlphanumericRandomValueStringGenerator(int length) {
        super(DEFAULT_CODEC, length);
    }
}
