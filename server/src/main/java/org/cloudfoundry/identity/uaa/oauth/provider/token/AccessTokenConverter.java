package org.cloudfoundry.identity.uaa.oauth.provider.token;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;

import java.util.Map;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public interface AccessTokenConverter {

    final String AUD = "aud";

    final String CLIENT_ID = "client_id";

    final String EXP = "exp";

    final String JTI = "jti";

    final String GRANT_TYPE = "grant_type";

    final String ATI = "ati";

    final String SCOPE = OAuth2AccessToken.SCOPE;

    final String AUTHORITIES = "authorities";

    /**
     * @param token an access token
     * @param authentication the current OAuth authentication
     * 
     * @return a map representation of the token suitable for a JSON response
     * 
     */
    Map<String, Object> convertAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication);

    /**
     * Recover an access token from the converted value. Half the inverse of
     * {@link #convertAccessToken(OAuth2AccessToken, OAuth2Authentication)}.
     * 
     * @param value the token value
     * @param map information decoded from an access token
     * @return an access token
     */
    OAuth2AccessToken extractAccessToken(String value, Map<String, ?> map);

    /**
     * Recover an {@link OAuth2Authentication} from the converted access token. Half the inverse of
     * {@link #convertAccessToken(OAuth2AccessToken, OAuth2Authentication)}.
     * 
     * @param map information decoded from an access token
     * @return an authentication representing the client and user (if there is one)
     */
    OAuth2Authentication extractAuthentication(Map<String, ?> map);

}