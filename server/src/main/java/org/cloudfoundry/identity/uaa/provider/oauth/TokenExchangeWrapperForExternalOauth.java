package org.cloudfoundry.identity.uaa.provider.oauth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class TokenExchangeWrapperForExternalOauth implements AuthenticationManager {

    private final ExternalOAuthAuthenticationManager delegate;

    public TokenExchangeWrapperForExternalOauth(final ExternalOAuthAuthenticationManager authenticationManager) {
        this.delegate = authenticationManager;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication instanceof ExternalOAuthCodeToken token) {
            if (token.getIdToken() == null) {
                    token = new TokenExchangeData(
                            token.getCode(),
                            token.getOrigin(),
                            token.getRedirectUrl(),
                            token.getAccessToken(),
                            token.getAccessToken(),
                            token.getSignedRequest(),
                            token.getUaaAuthenticationDetails()
                    );
            }
            return this.delegate.authenticate(token);
        }
        throw new IllegalArgumentException("authentication token be be of type: "  +
                ExternalOAuthCodeToken.class.getName());
    }
}
