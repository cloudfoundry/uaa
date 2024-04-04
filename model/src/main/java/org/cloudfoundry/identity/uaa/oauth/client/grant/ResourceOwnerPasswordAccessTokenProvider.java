package org.cloudfoundry.identity.uaa.oauth.client.grant;

import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2AccessDeniedException;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ResourceOwnerPasswordResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.UserRedirectRequiredException;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.OAuth2AccessTokenSupport;
import org.springframework.http.HttpHeaders;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Iterator;
import java.util.List;

public class ResourceOwnerPasswordAccessTokenProvider extends OAuth2AccessTokenSupport implements AccessTokenProvider {

	public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
		return resource instanceof ResourceOwnerPasswordResourceDetails && "password".equals(resource.getGrantType());
	}

	public boolean supportsRefresh(OAuth2ProtectedResourceDetails resource) {
		return supportsResource(resource);
	}

	public OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource,
			OAuth2RefreshToken refreshToken, AccessTokenRequest request) throws UserRedirectRequiredException, OAuth2AccessDeniedException {
		MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
		form.add(OAuth2Utils.GRANT_TYPE, "refresh_token");
		form.add("refresh_token", refreshToken.getValue());
		return retrieveToken(request, resource, form, new HttpHeaders());
	}

	public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details, AccessTokenRequest request)
			throws UserRedirectRequiredException, AccessDeniedException, OAuth2AccessDeniedException {

		ResourceOwnerPasswordResourceDetails resource = (ResourceOwnerPasswordResourceDetails) details;
		return retrieveToken(request, resource, getParametersForTokenRequest(resource, request), new HttpHeaders());

	}

	private MultiValueMap<String, String> getParametersForTokenRequest(ResourceOwnerPasswordResourceDetails resource, AccessTokenRequest request) {

		MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
		form.set(OAuth2Utils.GRANT_TYPE, "password");

		form.set("username", resource.getUsername());
		form.set("password", resource.getPassword());
		form.putAll(request);

		if (resource.isScoped()) {

			StringBuilder builder = new StringBuilder();
			List<String> scope = resource.getScope();

			if (scope != null) {
				Iterator<String> scopeIt = scope.iterator();
				while (scopeIt.hasNext()) {
					builder.append(scopeIt.next());
					if (scopeIt.hasNext()) {
						builder.append(' ');
					}
				}
			}

			form.set("scope", builder.toString());
		}

		return form;

	}

}
