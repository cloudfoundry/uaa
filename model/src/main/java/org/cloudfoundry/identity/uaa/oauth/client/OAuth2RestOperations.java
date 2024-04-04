package org.cloudfoundry.identity.uaa.oauth.client;

import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.UserRedirectRequiredException;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.springframework.web.client.RestOperations;

public interface OAuth2RestOperations extends RestOperations {

	OAuth2AccessToken getAccessToken() throws UserRedirectRequiredException;

	OAuth2ClientContext getOAuth2ClientContext();
	
	OAuth2ProtectedResourceDetails getResource();

}
