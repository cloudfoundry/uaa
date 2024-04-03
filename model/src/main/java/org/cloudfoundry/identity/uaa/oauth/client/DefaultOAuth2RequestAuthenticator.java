package org.cloudfoundry.identity.uaa.oauth.client;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.security.oauth2.client.http.AccessTokenRequiredException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.util.StringUtils;

public class DefaultOAuth2RequestAuthenticator implements OAuth2RequestAuthenticator {

	@Override
	public void authenticate(OAuth2ProtectedResourceDetails resource, OAuth2ClientContext clientContext,
			ClientHttpRequest request) {
		OAuth2AccessToken accessToken = clientContext.getAccessToken();
		if (accessToken == null) {
			throw new AccessTokenRequiredException(resource);
		}
		String tokenType = accessToken.getTokenType();
		if (!StringUtils.hasText(tokenType)) {
			tokenType = OAuth2AccessToken.BEARER_TYPE;
		} else if (tokenType.equalsIgnoreCase(OAuth2AccessToken.BEARER_TYPE)) {
			tokenType = OAuth2AccessToken.BEARER_TYPE;
		}
		request.getHeaders().set("Authorization", String.format("%s %s", tokenType, accessToken.getValue()));
	}

}
