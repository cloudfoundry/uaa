package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EXTERNAL_ATTR;

public class TestTokenEnhancer implements UaaTokenEnhancer {

    @Override
    public Map<String, String> getExternalAttributes(OAuth2Authentication authentication) {
        Map<String, String> externalAttributes = new HashMap<>();
        externalAttributes.put("purpose", "test");
        return externalAttributes;
    }

    @Override
    public Map<String, Object> enhance(Map<String, Object> claims, OAuth2Authentication authentication) {
        List<String> externalGroups = new ArrayList<>();
        externalGroups.add("admin");
        externalGroups.add("editor");

        Map<String, String> externalProperties = new HashMap<>();
        externalProperties.put("country", "nz");

        Map<String, Object> externalContext = new HashMap<>();
        externalContext.put("ex_groups", externalGroups);
        externalContext.put("ex_prop", externalProperties);

        externalContext.put(EXTERNAL_ATTR, getExternalAttributes(authentication));

        return externalContext;
    }

}
