package org.cloudfoundry.identity.uaa.oauth;

import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.Map;

public interface UaaTokenEnhancer {

    Map<String,String> getExternalAttributes(OAuth2Authentication authentication);


}
