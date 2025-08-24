package org.cloudfoundry.identity.uaa.oauth.pkce.verifiers;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SHA-256 code challenge method implementation.
 * 
 * @author Zoltan Maradics
 *
 */
public class S256PkceVerifier implements PkceVerifier {

    private static final Logger logger = LoggerFactory.getLogger(S256PkceVerifier.class);
    private final String codeChallengeMethod = "S256";

    public S256PkceVerifier() {
    }

    @Override
    public boolean verify(String codeVerifier, String codeChallenge) {
        if (codeVerifier == null || codeChallenge == null) {
            return false;
        }
        return codeChallenge.contentEquals(compute(codeVerifier));
    }

    public String compute(String codeVerifier) {
        try {
            byte[] bytes = codeVerifier.getBytes("US-ASCII");
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(bytes, 0, bytes.length);
            byte[] digest = md.digest();
            return Base64.encodeBase64URLSafeString(digest);
        } catch (UnsupportedEncodingException e) {
            logger.debug(e.getMessage(), e);
        } catch (NoSuchAlgorithmException e) {
            logger.debug(e.getMessage(), e);
        }
        return null;
    }

    @Override
    public String getCodeChallengeMethod() {
        return codeChallengeMethod;
    }
}
