package org.cloudfoundry.identity.uaa.oauth;

import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EXTERNAL_ATTR;

import java.util.HashMap;
import java.util.Map;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

public interface UaaTokenEnhancer {

  Map<String, String> getExternalAttributes(OAuth2Authentication authentication);

  default Map<String, Object> enhance(
      Map<String, Object> claims, OAuth2Authentication authentication) {
    Map<String, Object> result = new HashMap<>();
    result.put(EXTERNAL_ATTR, getExternalAttributes(authentication));
    return result;
  }
}
