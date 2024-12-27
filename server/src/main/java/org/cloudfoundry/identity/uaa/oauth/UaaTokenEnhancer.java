package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;

import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EXTERNAL_ATTR;

public interface UaaTokenEnhancer {

    Map<String, String> getExternalAttributes(OAuth2Authentication authentication);

    default Map<String, Object> enhance(Map<String, Object> claims, OAuth2Authentication authentication) {
        Map<String, Object> result = new HashMap<>();
        result.put(EXTERNAL_ATTR, getExternalAttributes(authentication));
        return result;
    }
}
