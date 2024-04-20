package org.cloudfoundry.identity.uaa.oauth.token.auth;

import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.common.AuthenticationScheme;
import org.springframework.http.HttpHeaders;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public class DefaultClientAuthenticationHandler implements ClientAuthenticationHandler {

	public void authenticateTokenRequest(OAuth2ProtectedResourceDetails resource, MultiValueMap<String, String> form,
			HttpHeaders headers) {
		if (resource.isAuthenticationRequired()) {
			AuthenticationScheme scheme = AuthenticationScheme.header;
			if (resource.getClientAuthenticationScheme() != null) {
				scheme = resource.getClientAuthenticationScheme();
			}
			String clientSecret = resource.getClientSecret();
			clientSecret = clientSecret == null ? "" : clientSecret;
			switch (scheme) {
			case header:
				form.remove("client_secret");
				headers.add(
						"Authorization",
						String.format(
								"Basic %s",
								new String(Base64.getEncoder().encode(String.format("%s:%s", resource.getClientId(),
										clientSecret).getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8)));
				break;
			case form, query:
				form.set("client_id", resource.getClientId());
				if (StringUtils.hasText(clientSecret)) {
					form.set("client_secret", clientSecret);
				}
				break;
			default:
				throw new IllegalStateException(
						"Default authentication handler doesn't know how to handle scheme: " + scheme);
			}
		}
	}
}
