package org.cloudfoundry.identity.app.web;

import org.springframework.web.client.RestOperations;

public class OpenIdClientFilter {

	public RestOperations restTemplate;

	public void setRestTemplate(RestOperations restTemplate) {
		this.restTemplate = restTemplate;		
	}

}
