package org.cloudfoundry.identity.uaa.oauth.client.resource;

public class ResourceOwnerPasswordResourceDetails extends BaseOAuth2ProtectedResourceDetails {
	
	private String username;
	
	private String password;
	
	public ResourceOwnerPasswordResourceDetails() {
		setGrantType("password");
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}	
	
}
