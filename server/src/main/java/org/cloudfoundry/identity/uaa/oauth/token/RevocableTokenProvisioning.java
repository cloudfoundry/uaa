package org.cloudfoundry.identity.uaa.oauth.token;

import java.util.List;
import org.cloudfoundry.identity.uaa.resources.ResourceManager;

public interface RevocableTokenProvisioning extends ResourceManager<RevocableToken> {

  int deleteRefreshTokensForClientAndUserId(String clientId, String userId, String zoneId);

  List<RevocableToken> getUserTokens(String userId, String zoneId);

  List<RevocableToken> getUserTokens(String userId, String clientId, String zoneId);

  List<RevocableToken> getClientTokens(String clientId, String zoneId);
}
