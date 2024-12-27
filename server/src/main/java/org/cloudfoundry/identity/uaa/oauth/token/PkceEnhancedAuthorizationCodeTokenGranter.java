package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.code.AuthorizationCodeServices;
import org.cloudfoundry.identity.uaa.oauth.provider.code.AuthorizationCodeTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;

public class PkceEnhancedAuthorizationCodeTokenGranter extends AuthorizationCodeTokenGranter {

    private final AuthorizationCodeServices authorizationCodeServices;

    private PkceValidationService pkceValidationService;

    public PkceEnhancedAuthorizationCodeTokenGranter(AuthorizationServerTokenServices tokenServices,
            AuthorizationCodeServices authorizationCodeServices, ClientDetailsService clientDetailsService,
            OAuth2RequestFactory requestFactory) {
        super(tokenServices, authorizationCodeServices, clientDetailsService, requestFactory);
        this.authorizationCodeServices = authorizationCodeServices;
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        return getOAuth2Authentication(client, tokenRequest, authorizationCodeServices, pkceValidationService);
    }

    public PkceValidationService getPkceValidationService() {
        return pkceValidationService;
    }

    public void setPkceValidationService(PkceValidationService pkceValidationService) {
        this.pkceValidationService = pkceValidationService;
    }

}
