package org.cloudfoundry.identity.uaa.oauth.pkce.verifiers;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.util.Base64;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceVerifier;

/**
 * SHA-256 code challenge method implementation.
 * 
 * @author Zoltan Maradics
 *
 */
public class S256PkceVerifier implements PkceVerifier {

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
            byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(bytes, 0, bytes.length);
            byte[] digest = md.digest();
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed by the JCA spec; unreachable in practice.
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String getCodeChallengeMethod() {
        return codeChallengeMethod;
    }
}
