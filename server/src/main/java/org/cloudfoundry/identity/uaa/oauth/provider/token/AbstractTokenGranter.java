package org.cloudfoundry.identity.uaa.oauth.provider.token;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;

import java.util.Collection;

public abstract class AbstractTokenGranter implements TokenGranter {
	
	protected final Log logger = LogFactory.getLog(getClass());

	private final AuthorizationServerTokenServices tokenServices;

	private final ClientDetailsService clientDetailsService;
	
	private final OAuth2RequestFactory requestFactory;
	
	private final String grantType;

	protected AbstractTokenGranter(AuthorizationServerTokenServices tokenServices,
			ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory, String grantType) {
		this.clientDetailsService = clientDetailsService;
		this.grantType = grantType;
		this.tokenServices = tokenServices;
		this.requestFactory = requestFactory;
	}

	public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {

		if (!this.grantType.equals(grantType)) {
			return null;
		}
		
		String clientId = tokenRequest.getClientId();
		ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
		validateGrantType(grantType, client);

		if (logger.isDebugEnabled()) {
			logger.debug("Getting access token for clientId");
		}

		return getAccessToken(client, tokenRequest);

	}

	protected OAuth2AccessToken getAccessToken(ClientDetails client, TokenRequest tokenRequest) {
		return tokenServices.createAccessToken(getOAuth2Authentication(client, tokenRequest));
	}

	protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
		OAuth2Request storedOAuth2Request = requestFactory.createOAuth2Request(client, tokenRequest);
		return new OAuth2Authentication(storedOAuth2Request, null);
	}

	protected void validateGrantType(String grantType, ClientDetails clientDetails) {
		Collection<String> authorizedGrantTypes = clientDetails.getAuthorizedGrantTypes();
		if (authorizedGrantTypes != null && !authorizedGrantTypes.isEmpty()
				&& !authorizedGrantTypes.contains(grantType)) {
			throw new InvalidClientException("Unauthorized grant type");
		}
	}

	protected AuthorizationServerTokenServices getTokenServices() {
		return tokenServices;
	}
	
	protected OAuth2RequestFactory getRequestFactory() {
		return requestFactory;
	}

}
