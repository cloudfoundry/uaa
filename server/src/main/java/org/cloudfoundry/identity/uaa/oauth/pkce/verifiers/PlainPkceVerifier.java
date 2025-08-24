package org.cloudfoundry.identity.uaa.oauth.pkce.verifiers;

import org.cloudfoundry.identity.uaa.oauth.pkce.PkceVerifier;

/**
 * Plain code challenge method implementation.
 * 
 * @author Zoltan Maradics
 *
 */
public class PlainPkceVerifier implements PkceVerifier {

    private final String codeChallengeMethod = "plain";

    @Override
    public boolean verify(String codeVerifier, String codeChallenge) {
        if (codeVerifier == null || codeChallenge == null) {
            return false;
        }
        return codeChallenge.equals(codeVerifier);
    }

    @Override
    public String getCodeChallengeMethod() {
        return codeChallengeMethod;
    }
}
