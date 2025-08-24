package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;

public class TokenExchangeData extends ExternalOAuthCodeToken {
    public TokenExchangeData(
            String code,
            String origin,
            String redirectUrl,
            String idToken,
            String accessToken,
            String signedRequest,
            UaaAuthenticationDetails details
    ) {
        super(code, origin, redirectUrl, idToken, accessToken, signedRequest, details);
    }


}
