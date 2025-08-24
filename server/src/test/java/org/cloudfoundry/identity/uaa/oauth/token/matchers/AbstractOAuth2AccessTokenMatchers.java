package org.cloudfoundry.identity.uaa.oauth.token.matchers;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;

import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public abstract class AbstractOAuth2AccessTokenMatchers<T> extends TypeSafeMatcher<T> {

    protected Matcher<?> value;
    public static ThreadLocal<Map<String, RevocableToken>> revocableTokens = ThreadLocal.withInitial(Collections::emptyMap);
    private final KeyInfoService keyInfoService;

    public AbstractOAuth2AccessTokenMatchers(Matcher<?> value) {
        this();
        this.value = value;
    }

    protected AbstractOAuth2AccessTokenMatchers() {
        keyInfoService = new KeyInfoService("https://localhost/uaa");
    }

    protected String getToken(String token) {
        if (revocableTokens.get().containsKey(token)) {
            return revocableTokens.get().get(token).getValue();
        } else {
            return token;
        }
    }

    @Override
    protected abstract boolean matchesSafely(T token);

    protected Map<String, Object> getClaims(T token) {
        String tokenValue;
        if (token instanceof OAuth2AccessToken accessToken) {
            tokenValue = accessToken.getValue();
        } else if (token instanceof OAuth2RefreshToken refreshToken) {
            tokenValue = refreshToken.getValue();
        } else {
            throw new IllegalArgumentException("token must be instanceof OAuth2AccessToken or OAuth2RefreshToken");
        }

        Jwt tokenJwt = JwtHelper.decode(getToken(tokenValue));
        assertThat(tokenJwt).isNotNull();
        Map<String, Object> claims;
        try {
            claims = JsonUtils.readValue(tokenJwt.getClaims(), new TypeReference<>() {
            });
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to decode token", e);
        }
        tokenJwt.verifySignature(keyInfoService.getKey(tokenJwt.getHeader().getKid()).getVerifier());
        return claims;
    }
}
