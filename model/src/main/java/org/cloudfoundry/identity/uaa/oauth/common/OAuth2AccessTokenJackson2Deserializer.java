package org.cloudfoundry.identity.uaa.oauth.common;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;

import java.io.IOException;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

public final class OAuth2AccessTokenJackson2Deserializer extends StdDeserializer<OAuth2AccessToken> {

	public OAuth2AccessTokenJackson2Deserializer() {
		super(OAuth2AccessToken.class);
	}

	@Override
	public OAuth2AccessToken deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {

		String tokenValue = null;
		String tokenType = null;
		String refreshToken = null;
		Long expiresIn = null;
		Set<String> scope = null;
		Map<String, Object> additionalInformation = new LinkedHashMap<String, Object>();

		while (jp.nextToken() != JsonToken.END_OBJECT) {
			String name = jp.getCurrentName();
			jp.nextToken();
			if (OAuth2AccessToken.ACCESS_TOKEN.equals(name)) {
				tokenValue = jp.getText();
			}
			else if (OAuth2AccessToken.TOKEN_TYPE.equals(name)) {
				tokenType = jp.getText();
			}
			else if (OAuth2AccessToken.REFRESH_TOKEN.equals(name)) {
				refreshToken = jp.getText();
			}
			else if (OAuth2AccessToken.EXPIRES_IN.equals(name)) {
				try {
					expiresIn = jp.getLongValue();
				} catch (JsonParseException e) {
					expiresIn = Long.valueOf(jp.getText());
				}
			}
			else if (OAuth2AccessToken.SCOPE.equals(name)) {
				scope = parseScope(jp);
			} else {
				additionalInformation.put(name, jp.readValueAs(Object.class));
			}
		}

		DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken(tokenValue);
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

	private Set<String> parseScope(JsonParser jp) throws JsonParseException, IOException {
		Set<String> scope;
		if (jp.getCurrentToken() == JsonToken.START_ARRAY) {
			scope = new TreeSet<>();
			while (jp.nextToken() != JsonToken.END_ARRAY) {
				scope.add(jp.getValueAsString());
			}
		} else {
			String text = jp.getText();
			scope = OAuth2Utils.parseParameterList(text);
		}
		return scope;
	}
}