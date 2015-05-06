/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.oauth.token;

import java.io.IOException;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.util.Assert;

@JsonSerialize(using = OpenIdToken.OpenIdTokenJackson1Serializer.class)
@JsonDeserialize(using = OpenIdToken.OpenIdTokenJackson1Deserializer.class)
public class OpenIdToken extends DefaultOAuth2AccessToken {

    public static String ID_TOKEN = "id_token";

    public String getIdTokenValue() {
        return idTokenValue;
    }

    public void setIdTokenValue(String idTokenValue) {
        this.idTokenValue = idTokenValue;
    }

    private String idTokenValue;

    public OpenIdToken(String accessTokenValue) {
        super(accessTokenValue);
    }

    public OpenIdToken(OAuth2AccessToken accessToken) {
        super(accessToken);
    }

    public static final class OpenIdTokenJackson1Serializer extends StdSerializer<OAuth2AccessToken> {

        public OpenIdTokenJackson1Serializer() {
            super(OAuth2AccessToken.class);
        }

        @Override
        public void serialize(OAuth2AccessToken token, JsonGenerator jgen, SerializerProvider provider) throws IOException {

            jgen.writeStartObject();
            jgen.writeStringField(OAuth2AccessToken.ACCESS_TOKEN, token.getValue());
            jgen.writeStringField(OAuth2AccessToken.TOKEN_TYPE, token.getTokenType());
            if (token instanceof OpenIdToken && ((OpenIdToken)token).getIdTokenValue()!=null) {
                jgen.writeStringField(ID_TOKEN, ((OpenIdToken) token).getIdTokenValue());
            }
            OAuth2RefreshToken refreshToken = token.getRefreshToken();
            if (refreshToken != null) {
                jgen.writeStringField(OAuth2AccessToken.REFRESH_TOKEN, refreshToken.getValue());
            }
            Date expiration = token.getExpiration();
            if (expiration != null) {
                long now = System.currentTimeMillis();
                jgen.writeNumberField(OAuth2AccessToken.EXPIRES_IN, (expiration.getTime() - now) / 1000);
            }
            Set<String> scope = token.getScope();
            if (scope != null && !scope.isEmpty()) {
                StringBuffer scopes = new StringBuffer();
                for (String s : scope) {
                    Assert.hasLength(s, "Scopes cannot be null or empty. Got " + scope + "");
                    scopes.append(s);
                    scopes.append(" ");
                }
                jgen.writeStringField(OAuth2AccessToken.SCOPE, scopes.substring(0, scopes.length() - 1));
            }
            Map<String, Object> additionalInformation = token.getAdditionalInformation();
            for (String key : additionalInformation.keySet()) {
                jgen.writeObjectField(key, additionalInformation.get(key));
            }
            jgen.writeEndObject();
        }
    }

    public final class OpenIdTokenJackson1Deserializer extends StdDeserializer<OAuth2AccessToken> {

        public OpenIdTokenJackson1Deserializer() {
            super(OAuth2AccessToken.class);
        }

        @Override
        public OAuth2AccessToken deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {

            String idTokenValue = null;
            String tokenValue = null;
            String tokenType = null;
            String refreshToken = null;
            Long expiresIn = null;
            Set<String> scope = null;
            Map<String, Object> additionalInformation = new LinkedHashMap<String, Object>();

            // TODO What should occur if a parameter exists twice
            while (jp.nextToken() != JsonToken.END_OBJECT) {
                String name = jp.getCurrentName();
                jp.nextToken();
                if (OAuth2AccessToken.ACCESS_TOKEN.equals(name)) {
                    tokenValue = jp.getText();
                } else if (ID_TOKEN.equals(name)) {
                    idTokenValue = jp.getText();
                } else if (OAuth2AccessToken.TOKEN_TYPE.equals(name)) {
                    tokenType = jp.getText();
                } else if (OAuth2AccessToken.REFRESH_TOKEN.equals(name)) {
                    refreshToken = jp.getText();
                } else if (OAuth2AccessToken.EXPIRES_IN.equals(name)) {
                    try {
                        expiresIn = jp.getLongValue();
                    } catch (JsonParseException e) {
                        expiresIn = Long.valueOf(jp.getText());
                    }
                } else if (OAuth2AccessToken.SCOPE.equals(name)) {
                    String text = jp.getText();
                    scope = OAuth2Utils.parseParameterList(text);
                } else {
                    additionalInformation.put(name, jp.readValueAs(Object.class));
                }
            }

            // TODO What should occur if a required parameter (tokenValue or tokenType) is missing?

            OpenIdToken accessToken = new OpenIdToken(tokenValue);
            accessToken.setIdTokenValue(idTokenValue);
            accessToken.setTokenType(tokenType);
            if (expiresIn != null) {
                accessToken.setExpiration(new Date(System.currentTimeMillis() + (expiresIn * 1000)));
            }
            if (refreshToken != null) {
                accessToken.setRefreshToken(new DefaultOAuth2RefreshToken(refreshToken));
            }
            accessToken.setScope(scope);
            accessToken.setAdditionalInformation(additionalInformation);

            return accessToken;
        }
    }
}
