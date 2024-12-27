package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AbstractTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.security.beans.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;

public class JwtTokenGranter extends AbstractTokenGranter {
    final DefaultSecurityContextAccessor defaultSecurityContextAccessor;

    public JwtTokenGranter(AuthorizationServerTokenServices tokenServices,
            MultitenantClientServices clientDetailsService,
            OAuth2RequestFactory requestFactory) {
        super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE_JWT_BEARER);
        defaultSecurityContextAccessor = new DefaultSecurityContextAccessor();
    }

    protected Authentication validateRequest(TokenRequest request) {
        if (defaultSecurityContextAccessor.isUser()) {
            if (request == null ||
                    request.getRequestParameters() == null ||
                    request.getRequestParameters().isEmpty()) {
                throw new InvalidGrantException("Missing token request object");
            }
            if (request.getRequestParameters().get("grant_type") == null) {
                throw new InvalidGrantException("Missing grant type");
            }
            if (!GRANT_TYPE_JWT_BEARER.equals(request.getRequestParameters().get("grant_type"))) {
                throw new InvalidGrantException("Invalid grant type");
            }
        } else {
            throw new InvalidGrantException("User authentication not found");
        }
        return SecurityContextHolder.getContext().getAuthentication();
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {

        Authentication userAuth = validateRequest(tokenRequest);
        OAuth2Request storedOAuth2Request = getRequestFactory().createOAuth2Request(client, tokenRequest);
        return new OAuth2Authentication(storedOAuth2Request, userAuth);
    }
}
