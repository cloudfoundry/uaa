package org.cloudfoundry.identity.uaa.oauth.common;

import lombok.Data;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TreeSet;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 * <p/>
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 * <p/>
 * Scope: OAuth2 client
 */
@Data
public class DefaultOAuth2AccessToken implements Serializable, OAuth2AccessToken {

    @Serial
    private static final long serialVersionUID = -1301199046022198244L;

    /**
     *  The token value.
     */
    private String value;

    /**
     *  The instant the token expires.
     */
    private Date expiration;

    /**
     *  The token type, as introduced in draft 11 of the OAuth 2 spec.
     *  The spec doesn't define (yet) that the valid token types are,
     *  but says it's required so the default will just be "undefined".
     */
    private String tokenType = BEARER_TYPE.toLowerCase();

    /**
     *  The refresh token associated with the access token, if any.
     */
    private transient OAuth2RefreshToken refreshToken;

    private Set<String> scopeSet;

    /**
     *  Additional information that token granters would like to add to the token, e.g., to support new token types.
     * (default empty)
     */
    private transient Map<String, Object> additionalInformation = Collections.emptyMap();

    /**
     * Create an access token from the value provided.
     */
    public DefaultOAuth2AccessToken(String value) {
        this.value = value;
    }

    /**
     * Private constructor for JPA and other serialization tools.
     */
    @SuppressWarnings("unused")
    private DefaultOAuth2AccessToken() {
        this((String) null);
    }

    /**
     * Copy constructor for access token.
     * 
     * @param accessToken a OAuth2AccessToken
     */
    public DefaultOAuth2AccessToken(OAuth2AccessToken accessToken) {
        this(accessToken.getValue());
        setAdditionalInformation(accessToken.getAdditionalInformation());
        setRefreshToken(accessToken.getRefreshToken());
        setExpiration(accessToken.getExpiration());
        setScope(accessToken.getScope());
        setTokenType(accessToken.getTokenType());
    }

    public int getExpiresIn() {
        return expiration != null ? (int) ((expiration.getTime() - System.currentTimeMillis()) / 1000L) : 0;
    }

    protected void setExpiresIn(int delta) {
        setExpiration(new Date(System.currentTimeMillis() + delta));
    }

    /**
     * Convenience method for checking expiration
     * 
     * @return true if the expiration is before the current time
     */
    public boolean isExpired() {
        return expiration != null && expiration.before(new Date());
    }

    /**
     * The scope of the token.
     * 
     * @return The scope of the token.
     */
    public Set<String> getScope() {
        return scopeSet;
    }

    /**
     * The scope of the token.
     * 
     * @param scope The scope of the token.
     */
    public void setScope(Set<String> scope) {
        this.scopeSet = scope;
    }

    @Override
    public boolean equals(Object obj) {
        return obj != null && toString().equals(obj.toString());
    }

    @Override
    public int hashCode() {
        return toString().hashCode();
    }

    @Override
    public String toString() {
        return getValue();
    }

    public static OAuth2AccessToken valueOf(Map<String, String> tokenParams) {
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(tokenParams.get(ACCESS_TOKEN));

        if (tokenParams.containsKey(EXPIRES_IN)) {
            long expiration = 0;
            try {
                // Convert to string before parseLong, tokenParams is not always a Map<String, String> might contain Integer
                expiration = Long.parseLong(String.valueOf(tokenParams.get(EXPIRES_IN)));
            }
            catch (NumberFormatException e) {
                // fall through...
            }
            token.setExpiration(new Date(System.currentTimeMillis() + (expiration * 1000L)));
        }

        if (tokenParams.containsKey(REFRESH_TOKEN)) {
            String refresh = tokenParams.get(REFRESH_TOKEN);
            DefaultOAuth2RefreshToken refreshToken = new DefaultOAuth2RefreshToken(refresh);
            token.setRefreshToken(refreshToken);
        }

        if (tokenParams.containsKey(SCOPE)) {
            Set<String> scope = new TreeSet<>();
            for (StringTokenizer tokenizer = new StringTokenizer(tokenParams.get(SCOPE), " ,"); tokenizer
                    .hasMoreTokens(); ) {
                scope.add(tokenizer.nextToken());
            }
            token.setScope(scope);
        }

        if (tokenParams.containsKey(TOKEN_TYPE)) {
            token.setTokenType(tokenParams.get(TOKEN_TYPE));
        }

        return token;
    }

    /**
     * Additional information that token granters would like to add to the token, e.g., to support new token types.
     * If the values in the map are primitive, then remote communication is going to always work.
     * It should also be safe to use maps (nested if desired), or something that is explicitly serializable by Jackson.
     * 
     * @param additionalInformation the additional information to set
     */
    public void setAdditionalInformation(Map<String, Object> additionalInformation) {
        this.additionalInformation = new LinkedHashMap<>(additionalInformation);
    }
}
