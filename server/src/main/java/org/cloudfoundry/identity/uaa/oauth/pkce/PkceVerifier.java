package org.cloudfoundry.identity.uaa.oauth.pkce;

/**
 * Each PKCE verifier MUST implement this interface to be able to be used
 * in PKCE validation service.
 * 
 * @author Zoltan Maradics
 *
 */
public interface PkceVerifier {

    /**
     * Verify that the code verifier matches the code challenge based on code challenge method.
     * code_challenge = code_challenge_method(code_verifier)
     * 
     * @param codeVerifier
     *            Code verifier parameter.
     * @param codeChallenge
     *            Code challenge parameter.
     * @return true: if code verifier transformed with code challenge method match
     *               with code challenge. 
     *         false: otherwise.
     */
    public boolean verify(String codeVerifier, String codeChallenge);

    /**
     * Getter for Code Challenge Method name.
     * 
     * @return
     */
    public String getCodeChallengeMethod();
}
