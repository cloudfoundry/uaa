package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.Serial;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 client
 */
public class DefaultAccessTokenRequest implements AccessTokenRequest, Serializable {

    @Serial
    private static final long serialVersionUID = -3327891152794747331L;

    private final MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();

    private transient Object state;

    private transient OAuth2AccessToken existingToken;

    private String currentUri;

    private String cookie;

    private transient Map<String, List<String>> headers = new LinkedMultiValueMap<>();

    public DefaultAccessTokenRequest() {
    }

    public DefaultAccessTokenRequest(Map<String, String[]> parameters) {
        if (parameters != null) {
            for (Entry<String, String[]> entry : parameters.entrySet()) {
                this.parameters.put(entry.getKey(), Arrays.asList(entry.getValue()));
            }
        }
    }

    public boolean isError() {
        return parameters.containsKey("error");
    }

    public Object getPreservedState() {
        return state;
    }

    public void setPreservedState(Object state) {
        this.state = state;
    }

    public String getStateKey() {
        return getFirst("state");
    }

    public void setStateKey(String state) {
        parameters.set("state", state);
    }

    /**
     * The current URI that is being handled on the client.
     * 
     * @return The URI.
     */

    public String getCurrentUri() {
        return currentUri;
    }

    public void setCurrentUri(String uri) {
        currentUri = uri;
    }

    /**
     * The authorization code for this context.
     * 
     * @return The authorization code, or null if none.
     */

    public String getAuthorizationCode() {
        return getFirst("code");
    }

    public void setAuthorizationCode(String code) {
        parameters.set("code", code);
    }

    public void setCookie(String cookie) {
        this.cookie = cookie;
    }

    public String getCookie() {
        return cookie;
    }

    public void setHeaders(Map<String, List<String>> headers) {
        this.headers = headers;
    }

    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    public void setExistingToken(OAuth2AccessToken existingToken) {
        this.existingToken = existingToken;
    }

    public OAuth2AccessToken getExistingToken() {
        return existingToken;
    }

    public String getFirst(String key) {
        return parameters.getFirst(key);
    }

    public void add(String key, String value) {
        parameters.add(key, value);
    }

    public void addAll(String key, List<? extends String> values) {
        for (String value : values) {
            this.add(key, value);
        }
    }

    public void addAll(MultiValueMap<String, String> map) {
        for (Entry<String, List<String>> entry : map.entrySet()) {
            this.addAll(entry.getKey(), entry.getValue());
        }
    }

    public void set(String key, String value) {
        parameters.set(key, value);
    }

    public void setAll(Map<String, String> values) {
        parameters.setAll(values);
    }

    public Map<String, String> toSingleValueMap() {
        return parameters.toSingleValueMap();
    }

    public int size() {
        return parameters.size();
    }

    public boolean isEmpty() {
        return parameters.isEmpty();
    }

    public boolean containsKey(Object key) {
        return parameters.containsKey(key);
    }

    public boolean containsValue(Object value) {
        return parameters.containsValue(value);
    }

    public List<String> get(Object key) {
        return parameters.get(key);
    }

    public List<String> put(String key, List<String> value) {
        return parameters.put(key, value);
    }

    public List<String> remove(Object key) {
        return parameters.remove(key);
    }

    public void putAll(Map<? extends String, ? extends List<String>> m) {
        parameters.putAll(m);
    }

    public void clear() {
        parameters.clear();
    }

    public Set<String> keySet() {
        return parameters.keySet();
    }

    public Collection<List<String>> values() {
        return parameters.values();
    }

    public Set<Entry<String, List<String>>> entrySet() {
        return parameters.entrySet();
    }

    public boolean equals(Object o) {
        return parameters.equals(o);
    }

    public int hashCode() {
        return parameters.hashCode();
    }

    public String toString() {
        return parameters.toString();
    }

}
