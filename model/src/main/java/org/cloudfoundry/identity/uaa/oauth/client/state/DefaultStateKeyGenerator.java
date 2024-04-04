package org.cloudfoundry.identity.uaa.oauth.client.state;

import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;


public class DefaultStateKeyGenerator implements StateKeyGenerator {

	private RandomValueStringGenerator generator = new RandomValueStringGenerator();

	public String generateKey(OAuth2ProtectedResourceDetails resource) {
		return generator.generate();
	}

}
