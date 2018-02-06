package org.cloudfoundry.identity.uaa.oauth;

import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class TestTokenEnhancer implements UaaTokenEnhancer {

    @Override
    public Map<String, String> getExternalAttributes(OAuth2Authentication authentication) {
        Map<String, String> externalAttributes = new HashMap<>();
        externalAttributes.put("purpose", "test");
        return externalAttributes;
    }

    @Override
    public Map<String, Object> getExternalContext(OAuth2Authentication authentication) {
        Map<String, Object> externalContext = new HashMap<String, Object>();
        ArrayList<String> externalGroups = new ArrayList<String>();
        Map<String, String> externalProperties = new HashMap<>();
        externalGroups.add("admin");
        externalGroups.add("editor");
        externalProperties.put("country", "nz");
        externalContext.put("groups", externalGroups);
        externalContext.put("prop", externalProperties);
        return externalContext;
    }

}
