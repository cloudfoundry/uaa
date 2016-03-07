package org.cloudfoundry.identity.uaa.provider.token;

import org.cloudfoundry.identity.uaa.oauth.OauthGrant;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

public class JwtBearerAssertionTokenGranter extends AbstractTokenGranter {
    
    protected JwtBearerAssertionTokenGranter(AuthorizationServerTokenServices tokenServices,
            ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory) {
        super(tokenServices, clientDetailsService, requestFactory, OauthGrant.JWT_BEARER);
    }

}
