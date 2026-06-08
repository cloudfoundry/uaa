package org.cloudfoundry.identity.uaa.oauth.common;

import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeToken;
import tools.jackson.core.exc.StreamReadException;

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 client
 */
public class OAuth2AccessTokenJackson2Deserializer extends StdDeserializer<OAuth2AccessToken> {

    public OAuth2AccessTokenJackson2Deserializer(Class<?> vc) {
        super(vc);
    }

    public OAuth2AccessTokenJackson2Deserializer() {
        super(OAuth2AccessToken.class);
    }

    @Override
    public OAuth2AccessToken deserialize(JsonParser jp, DeserializationContext ctxt) {

        String idTokenValue = null;
        String tokenValue = null;
        String tokenType = null;
        String refreshToken = null;
        Long expiresIn = null;
        Set<String> scope = null;
        Map<String, Object> additionalInformation = new LinkedHashMap<>();

        while (jp.nextToken() != JsonToken.END_OBJECT) {
            String name = jp.currentName();
            jp.nextToken();
            if (OAuth2AccessToken.ACCESS_TOKEN.equals(name)) {
                tokenValue = jp.getString();
            } else if (CompositeToken.ID_TOKEN.equals(name)) {
                idTokenValue = jp.getString();
            } else if (OAuth2AccessToken.TOKEN_TYPE.equals(name)) {
                tokenType = jp.getString();
            } else if (OAuth2AccessToken.REFRESH_TOKEN.equals(name)) {
                refreshToken = jp.getString();
            } else if (OAuth2AccessToken.EXPIRES_IN.equals(name)) {
                try {
                    expiresIn = jp.getLongValue();
                } catch (StreamReadException _) {
                    expiresIn = Long.valueOf(jp.getString());
                }
            } else if (OAuth2AccessToken.SCOPE.equals(name)) {
                scope = parseScope(jp);
            } else {
                additionalInformation.put(name, jp.readValueAs(Object.class));
            }
        }

        CompositeToken accessToken = new CompositeToken(tokenValue);
        accessToken.setIdTokenValue(idTokenValue);
        accessToken.setTokenType(tokenType);
        if (expiresIn != null && expiresIn != 0) {
            accessToken.setExpiration(new Date(System.currentTimeMillis() + (expiresIn * 1000)));
        }
        if (refreshToken != null) {
            accessToken.setRefreshToken(new DefaultOAuth2RefreshToken(refreshToken));
        }
        accessToken.setScope(scope);
        accessToken.setAdditionalInformation(additionalInformation);

        return accessToken;
    }

    private Set<String> parseScope(JsonParser jp) {
        Set<String> scope;
        if (jp.currentToken() == JsonToken.START_ARRAY) {
            scope = new TreeSet<>();
            while (jp.nextToken() != JsonToken.END_ARRAY) {
                scope.add(jp.getValueAsString());
            }
        } else {
            String text = jp.getString();
            scope = OAuth2Utils.parseParameterList(text);
        }
        return scope;
    }
}