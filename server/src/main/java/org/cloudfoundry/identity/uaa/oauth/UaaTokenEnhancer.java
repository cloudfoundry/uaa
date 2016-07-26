package org.cloudfoundry.identity.uaa.oauth;

import java.util.Map;

import org.springframework.security.oauth2.provider.OAuth2Authentication;

public interface UaaTokenEnhancer {
	
	Map<String,String> getExternalAttributes(OAuth2Authentication authentication);

}
