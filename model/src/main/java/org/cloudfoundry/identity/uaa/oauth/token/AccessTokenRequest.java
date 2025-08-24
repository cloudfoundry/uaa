package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.springframework.util.MultiValueMap;

import java.util.List;
import java.util.Map;

/**
 * Moved class AccessTokenRequest implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 client
 */
public interface AccessTokenRequest extends MultiValueMap<String, String> {

    OAuth2AccessToken getExistingToken();

    void setExistingToken(OAuth2AccessToken existingToken);

    void setAuthorizationCode(String code);

    String getAuthorizationCode();

    void setCurrentUri(String uri);

    String getCurrentUri();

    void setStateKey(String state);

    String getStateKey();

    void setPreservedState(Object state);

    Object getPreservedState();

    boolean isError();

    void setCookie(String cookie);

    String getCookie();

    void setHeaders(Map<String, List<String>> headers);

    Map<String, List<String>> getHeaders();

}