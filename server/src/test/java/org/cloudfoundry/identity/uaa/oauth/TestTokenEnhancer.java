package org.cloudfoundry.identity.uaa.oauth;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.oauth2.provider.OAuth2Authentication;

public class TestTokenEnhancer implements UaaTokenEnhancer {

	@Override
	public Map<String, String> getExternalAttributes(OAuth2Authentication authentication) {
		Map<String, String> externalAttributes = new HashMap<String, String>();
		externalAttributes.put("purpose", "test");
		return externalAttributes;
	}

}
