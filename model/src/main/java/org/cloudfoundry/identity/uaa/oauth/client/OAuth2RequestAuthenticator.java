package org.cloudfoundry.identity.uaa.oauth.client;

import org.springframework.http.client.ClientHttpRequest;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;

public interface OAuth2RequestAuthenticator {
	void authenticate(OAuth2ProtectedResourceDetails resource, OAuth2ClientContext clientContext, ClientHttpRequest request);

}
