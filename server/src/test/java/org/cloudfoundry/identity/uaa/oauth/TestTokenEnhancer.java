package org.cloudfoundry.identity.uaa.oauth;

import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.HashMap;
import java.util.Map;

public class TestTokenEnhancer implements UaaTokenEnhancer {

    @Override
    public Map<String, String> getExternalAttributes(OAuth2Authentication authentication) {
        Map<String, String> externalAttributes = new HashMap<>();
        externalAttributes.put("purpose", "test");
        return externalAttributes;
    }

}
