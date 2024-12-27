package org.cloudfoundry.identity.uaa.oauth.provider.implicit;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
@SuppressWarnings("serial")
public class ImplicitTokenRequest extends TokenRequest {

    private OAuth2Request oauth2Request;

    public ImplicitTokenRequest(TokenRequest tokenRequest, OAuth2Request oauth2Request) {
        super(tokenRequest.getRequestParameters(), tokenRequest.getClientId(), tokenRequest.getScope(), tokenRequest.getGrantType());
        this.oauth2Request = oauth2Request;
    }

    public OAuth2Request getOAuth2Request() {
        return oauth2Request;
    }

}
