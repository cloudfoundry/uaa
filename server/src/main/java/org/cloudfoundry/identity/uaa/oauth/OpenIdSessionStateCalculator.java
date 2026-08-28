package org.cloudfoundry.identity.uaa.oauth;


import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;

public class OpenIdSessionStateCalculator {
    private final Logger logger = LoggerFactory.getLogger(OpenIdSessionStateCalculator.class);
    private static final HexFormat HEX = HexFormat.of();
    private SecureRandom secureRandom;

    public OpenIdSessionStateCalculator() {
        this.secureRandom = new SecureRandom();
    }

    public String calculate(String currentUserId, String clientId, String origin) {
        byte[] array = new byte[32];
        secureRandom.nextBytes(array);
        String salt = HEX.formatHex(array);

        String text = "%s %s %s %s".formatted(clientId, origin, currentUserId, salt);
        byte[] hash;
        try {
            hash = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        logger.debug("Calculated OIDC session state for clientId={}, origin={}, sessionId=REDACTED, salt={}",
                UaaStringUtils.getCleanedUserControlString(clientId),
                UaaStringUtils.getCleanedUserControlString(origin),
                UaaStringUtils.getCleanedUserControlString(salt));
        return "%s.%s".formatted(HEX.formatHex(hash), salt);
    }

    public void setSecureRandom(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }
}
