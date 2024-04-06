package org.cloudfoundry.identity.uaa.oauth.provider.client;

import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AbstractTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public class ClientCredentialsTokenGranter extends AbstractTokenGranter {

	private static final String GRANT_TYPE = "client_credentials";
	private boolean allowRefresh = false;

	public ClientCredentialsTokenGranter(AuthorizationServerTokenServices tokenServices,
			ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory) {
		this(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE);
	}

	protected ClientCredentialsTokenGranter(AuthorizationServerTokenServices tokenServices,
			ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory, String grantType) {
		super(tokenServices, clientDetailsService, requestFactory, grantType);
	}
	
	public void setAllowRefresh(boolean allowRefresh) {
		this.allowRefresh = allowRefresh;
	}

	@Override
	public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
		OAuth2AccessToken token = super.grant(grantType, tokenRequest);
		if (token != null) {
			DefaultOAuth2AccessToken norefresh = new DefaultOAuth2AccessToken(token);
			// The spec says that client credentials should not be allowed to get a refresh token
			if (!allowRefresh) {
				norefresh.setRefreshToken(null);
			}
			token = norefresh;
		}
		return token;
	}

}
