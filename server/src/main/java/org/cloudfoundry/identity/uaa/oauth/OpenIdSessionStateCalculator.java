package org.cloudfoundry.identity.uaa.oauth;


import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class OpenIdSessionStateCalculator {
    private final String sessionId;
    private final String clientId;
    private final String origin;
    private final String salt;
    private final Logger logger = LoggerFactory.getLogger(OpenIdSessionStateCalculator.class);

    public OpenIdSessionStateCalculator(UaaAuthenticationDetails details, SecureRandom secureRandom) {
        this.sessionId = details.getSessionId();
        this.clientId = details.getClientId();
        this.origin = details.getOrigin();
        byte[] array = new byte[32];
        secureRandom.nextBytes(array);
        salt = DatatypeConverter.printHexBinary(array).toLowerCase();
    }

    public String calculate() {
        String text = String.format("%s %s %s %s", clientId, origin, sessionId, salt);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
            return String.format("%s.%s", DatatypeConverter.printHexBinary(hash).toLowerCase(), salt);
        } catch (NoSuchAlgorithmException e) {
            logger.error("Could not find algorithm SHA-256, aborting");
            return null;
        }
    }
}
