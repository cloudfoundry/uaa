package org.cloudfoundry.identity.uaa.oauth.provider;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.provider.client.ClientCredentialsTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.code.AuthorizationCodeServices;
import org.cloudfoundry.identity.uaa.oauth.provider.code.AuthorizationCodeTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.implicit.ImplicitTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.password.ResourceOwnerPasswordTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.refresh.RefreshTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationManager;

import java.util.ArrayList;
import java.util.List;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public class CompositeTokenGranter implements TokenGranter {

    private final List<TokenGranter> tokenGranters;

    @Deprecated(since = "This constructor is only used in unit tests", forRemoval = true)
    public CompositeTokenGranter(
            final @Qualifier("zoneAwareAuthzAuthenticationManager") AuthenticationManager authenticationManager,
            final @Qualifier("authorizationRequestManager") OAuth2RequestFactory oAuth2RequestFactory,
            final @Qualifier("jdbcClientDetailsService") ClientDetailsService clientDetailsService,
            final @Qualifier("authorizationCodeServices") AuthorizationCodeServices authorizationCodeServices,
            final @Qualifier("tokenServices") AuthorizationServerTokenServices tokenServices
    ) {
        this.tokenGranters = new ArrayList<>();
        this.tokenGranters.add(new AuthorizationCodeTokenGranter(tokenServices, authorizationCodeServices, clientDetailsService,
                oAuth2RequestFactory));
        this.tokenGranters.add(new RefreshTokenGranter(tokenServices, clientDetailsService, oAuth2RequestFactory));
        this.tokenGranters.add(new ImplicitTokenGranter(tokenServices, clientDetailsService, oAuth2RequestFactory));
        this.tokenGranters.add(new ClientCredentialsTokenGranter(tokenServices, clientDetailsService, oAuth2RequestFactory));
        if (authenticationManager != null) {
            this.tokenGranters.add(new ResourceOwnerPasswordTokenGranter(authenticationManager, tokenServices,
                    clientDetailsService, oAuth2RequestFactory));
        }
    }

    public CompositeTokenGranter(List<TokenGranter> tokenGranters) {
        this.tokenGranters = tokenGranters != null ? new ArrayList<>(tokenGranters) : new ArrayList<>();
    }

    public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
        for (TokenGranter granter : tokenGranters) {
            OAuth2AccessToken grant = granter.grant(grantType, tokenRequest);
            if (grant != null) {
                return grant;
            }
        }
        return null;
    }

    public void addTokenGranter(TokenGranter tokenGranter) {
        if (tokenGranter == null) {
            throw new IllegalArgumentException("Token granter is null");
        }
        tokenGranters.add(tokenGranter);
    }

}
