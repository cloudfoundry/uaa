package org.cloudfoundry.identity.uaa.oauth;


import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class OpenIdSessionStateCalculator {
    private final Logger logger = LoggerFactory.getLogger(OpenIdSessionStateCalculator.class);
    private SecureRandom secureRandom;

    public OpenIdSessionStateCalculator() {
        this.secureRandom = new SecureRandom();
    }

    public String calculate(String currentUserId, String clientId, String origin)  {
        byte[] array = new byte[32];
        secureRandom.nextBytes(array);
        String salt = Hex.encodeHexString(array).toLowerCase();

        String text = String.format("%s %s %s %s", clientId, origin, currentUserId, salt);
        byte[] hash = DigestUtils.sha256(text.getBytes(StandardCharsets.UTF_8));
        logger.debug(String.format("Calculated OIDC session state for clientId=%s, origin=%s, sessionId=REDACTED, salt=%s", clientId, origin, salt));
        return String.format("%s.%s", Hex.encodeHexString(hash).toLowerCase(), salt);
    }

    public void setSecureRandom(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }
}
