package org.cloudfoundry.identity.uaa.oauth.token.matchers;

import static org.junit.Assert.assertNotNull;

import java.util.Map;

import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;

import com.fasterxml.jackson.core.type.TypeReference;

public abstract class AbstractOAuth2AccessTokenMatchers<T> extends TypeSafeMatcher<T> {

    protected Matcher<?> value;

    public AbstractOAuth2AccessTokenMatchers(Matcher<?> value) {
		this.value = value;
    }

    protected AbstractOAuth2AccessTokenMatchers() {
    }

    @Override
    protected abstract boolean matchesSafely(T token);

    protected Map<String, Object> getClaims(T token) {
		String tokenValue = null;
		if (token instanceof OAuth2AccessToken)
			tokenValue = ((OAuth2AccessToken)token).getValue();
		else if (token instanceof OAuth2RefreshToken)
			tokenValue = ((OAuth2RefreshToken)token).getValue();
		else
			throw new IllegalArgumentException("token must be instanceof OAuth2AccessToken or OAuth2RefreshToken");

		Jwt tokenJwt = JwtHelper.decode(tokenValue);
		assertNotNull(tokenJwt);
		Map<String, Object> claims;
		try {
		    claims = JsonUtils.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
		} catch (Exception e) {
		    throw new IllegalArgumentException("Unable to decode token", e);
		}
        tokenJwt.verifySignature(KeyInfo.getKey(tokenJwt.getHeader().getKid()).getVerifier());
		return claims;
    }
}
