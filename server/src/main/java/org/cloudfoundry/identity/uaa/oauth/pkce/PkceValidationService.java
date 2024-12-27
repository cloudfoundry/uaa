package org.cloudfoundry.identity.uaa.oauth.pkce;

import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * PKCE Validation Service.
 *  - Validate Code Verifier parameter.
 *  - Validate Code Challenge parameter.
 *  - Validate Code Challenge Method parameter.
 *  - List supported code challenge methods.
 *  - Verify code verifier and code challenge based on code challenge method.
 *
 * @author Zoltan Maradics
 */

public class PkceValidationService {

    /*
     * Regular expression match with any string:
     *  - Length between 43 and 128
     *  - Contains only [A-Z],[a-z],[0-9],_,.,-,~ characters
     *  (Note: '_' is part of the 'w' in the pattern.)
     */
    private static final Pattern pattern = Pattern.compile("^[\\w\\.\\-\\~]{43,128}$");

    public static final String CODE_CHALLENGE = "code_challenge";
    public static final String CODE_CHALLENGE_METHOD = "code_challenge_method";
    public static final String CODE_VERIFIER = "code_verifier";

    private Map<String, PkceVerifier> pkceVerifiers;

    public PkceValidationService() {
        this(Collections.emptyMap());
    }

    public PkceValidationService(Map<String, PkceVerifier> pkceVerifiers) {
        this.pkceVerifiers = pkceVerifiers;
    }

    /**
     * Get all supported code challenge methods.
     * @return Set of supported code challenge methods.
     */
    public Set<String> getSupportedCodeChallengeMethods() {
        return this.pkceVerifiers.keySet();
    }

    /**
     * Check code challenge method is supported or not.
     * @param codeChallengeMethod
     *            Code challenge method parameter.
     * @return true if the code challenge method is supported.
     *         false otherwise.
     */
    public boolean isCodeChallengeMethodSupported(String codeChallengeMethod) {
        if (codeChallengeMethod == null) {
            return false;
        }
        return this.pkceVerifiers.containsKey(codeChallengeMethod);
    }

    /**
     * Check presence of PKCE parameters and validate.
     * @param requestParameters
     *        Map of query parameters of Authorization request.
     * @param codeVerifier
     *        Code verifier.
     * @param clientDetails
     *        Allow public information from client
     * @return true: (1) in case of Authorization Code Grant without PKCE.
     *               (2) in case of Authorization Code Grant with PKCE and code verifier
     *                   matched with code challenge based on code challenge method.
     *         false: in case of Authorization Code Grant with PKCE and code verifier
     *                does not match with code challenge based on code challenge method.
     * @throws PkceValidationException
     *         (1) Code verifier must be provided for this authorization code.
     *         (2) Code verifier not required for this authorization code.
     */
    public boolean checkAndValidate(Map<String, String> requestParameters, String codeVerifier, ClientDetails clientDetails) throws PkceValidationException {
        if (!hasPkceParameters(requestParameters, codeVerifier)) {
            return true;
        }
        String codeChallengeMethod = extractCodeChallengeMethod(requestParameters);
        if (!"S256".equalsIgnoreCase(codeChallengeMethod) && clientDetails != null && clientDetails.getAdditionalInformation() != null
                && clientDetails.getAdditionalInformation().get(ClientConstants.ALLOW_PUBLIC) != null) {
            throw new InvalidGrantException("Public client must use code challange method S256");
        }
        return pkceVerifiers.get(codeChallengeMethod).verify(codeVerifier,
                requestParameters.get(PkceValidationService.CODE_CHALLENGE));
    }

    /**
     * Check if PKCE parameters are present. 
     * @param requestParameters
     *        Map of authorization request parameters.
     * @param codeVerifier
     *        Code verifier.
     * @return true: There are Code Challenge and Code Verifier parameters with not null value.
     *         false: There are no PKCE parameters.
     * @throws PkceValidationException
     *         (1) Code verifier must be provided for this authorization code.
     *         (2) Code verifier not required for this authorization code.
     */
    protected boolean hasPkceParameters(Map<String, String> requestParameters, String codeVerifier) throws PkceValidationException {
        String codeChallenge = requestParameters.get(CODE_CHALLENGE);
        if (codeChallenge != null) {
            if (codeVerifier != null && !codeVerifier.isEmpty()) {
                return true;
            } else {
                throw new PkceValidationException("Code verifier must be provided for this authorization code.");
            }
        } else if (codeVerifier != null && !codeVerifier.isEmpty()) {
            throw new PkceValidationException("Code verifier not required for this authorization code.");
        }
        return false;
    }

    /**
     * Extract code challenge method from request.
     * @param requestParameters: Authorization request parameters.
     * @return
     *        If there is no code challenge method in authorization request then return: "plain"
     *        Otherwise return the value of code challenge method parameter.
     */
    protected String extractCodeChallengeMethod(Map<String, String> requestParameters) {
        String codeChallengeMethod = requestParameters.get(CODE_CHALLENGE_METHOD);
        if (codeChallengeMethod == null) {
            return "plain";
        } else {
            return codeChallengeMethod;
        }
    }

    /**
     * Validate the code verifier parameter based on RFC 7636 recommendations.
     * 
     * @param codeVerifier: Code Verifier parameter from token request.
     * @return true or false based on evaluation.
     */
    public static boolean isCodeVerifierParameterValid(String codeVerifier) {
        return matchWithPattern(codeVerifier);
    }

    /**
     * Validate the code challenge parameter based on RFC 7636 recommendations.
     * 
     * @param codeChallenge: Code Challenge parameter from token request.
     * @return true or false based on evaluation.
     */
    public static boolean isCodeChallengeParameterValid(String codeChallenge) {
        return matchWithPattern(codeChallenge);
    }

    /**
     * Validate parameter with predefined regular expression (length and used
     * character set)
     * 
     * @param parameter: Code Verifier or Code Challenge
     * @return true or false based on parameter match with regular expression
     */
    protected static boolean matchWithPattern(String parameter) {
        if (parameter == null) {
            return false;
        }
        return pattern.matcher(parameter).matches();
    }
}
