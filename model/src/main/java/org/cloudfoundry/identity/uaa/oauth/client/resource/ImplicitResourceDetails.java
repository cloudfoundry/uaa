package org.cloudfoundry.identity.uaa.oauth.client.resource;

public class ImplicitResourceDetails extends AbstractRedirectResourceDetails {

	public ImplicitResourceDetails() {
		setGrantType("implicit");
	}

}
