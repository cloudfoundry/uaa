package org.cloudfoundry.identity.uaa.oauth.client.test;

import org.springframework.web.client.RestOperations;

public interface RestTemplateHolder {

	void setRestTemplate(RestOperations restTemplate);

	RestOperations getRestTemplate();

}
