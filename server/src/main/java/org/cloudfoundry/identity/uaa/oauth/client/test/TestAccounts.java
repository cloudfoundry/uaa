package org.cloudfoundry.identity.uaa.oauth.client.test;

import org.cloudfoundry.identity.uaa.oauth.client.resource.ClientCredentialsResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ImplicitResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ResourceOwnerPasswordResourceDetails;

public interface TestAccounts {

	String getUserName();

	String getPassword();

	String getEmail();

	String getAdminClientId();

	String getAdminClientSecret();

	ClientCredentialsResourceDetails getDefaultClientCredentialsResource();

	ClientCredentialsResourceDetails getClientCredentialsResource(String clientId, String clientSecret);
	
	ResourceOwnerPasswordResourceDetails getDefaultResourceOwnerPasswordResource();

	ResourceOwnerPasswordResourceDetails getResourceOwnerPasswordResource(String[] scope, String clientId,
			String clientSecret, String username, String password);
	
	ImplicitResourceDetails getDefaultImplicitResource();

}