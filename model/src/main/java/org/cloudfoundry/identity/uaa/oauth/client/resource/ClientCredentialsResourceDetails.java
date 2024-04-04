package org.cloudfoundry.identity.uaa.oauth.client.resource;

public class ClientCredentialsResourceDetails extends BaseOAuth2ProtectedResourceDetails {
	
	public ClientCredentialsResourceDetails() {
		setGrantType("client_credentials");
	}
	
	@Override
	public boolean isClientOnly() {
		return true;
	}

}
