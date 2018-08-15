package org.cloudfoundry.identity.uaa.oauth;

import com.google.common.collect.Sets;
import org.bouncycastle.util.Strings;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeToken;
import org.cloudfoundry.identity.uaa.test.TestWebAppContext;
import org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_IMPLICIT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.junit.Assert.assertThat;


@ExtendWith(SpringExtension.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = TestWebAppContext.class)
public class UaaTokenServicesTests {
    @Autowired
    private UaaTokenServices tokenServices;

    @Value("${uaa.url}")
    private String uaaUrl;

    @Value("${oauth.clients.jku_test.id}")
    private String clientId;

    @Value("${oauth.clients.jku_test.secret}")
    private String clientSecret;

    @Value("${oauth.clients.jku_test.scope}")
    private String clientScopes;

    @Autowired
    private JdbcUaaUserDatabase jdbcUaaUserDatabase;

    @Nested
    @DisplayName("when building an id token")
    @ExtendWith(SpringExtension.class)
    @ActiveProfiles("default")
    @WebAppConfiguration
    @ContextConfiguration(classes = TestWebAppContext.class)
    class WhenBuildingAnIdToken {
        private String requestedScope;
        private String responseType;

        @BeforeEach
        void setupRequest() {
            requestedScope = "openid";
            responseType = "id_token";
        }

        @Test
        public void ensureJKUHeaderIsSetWhenBuildingAnIdToken() {
            AuthorizationRequest authorizationRequest = constructAuthorizationRequest(GRANT_TYPE_PASSWORD, requestedScope);
            authorizationRequest.setResponseTypes(Sets.newHashSet(responseType));

            OAuth2Authentication auth2Authentication = constructUserAuthenticationFromAuthzRequest(authorizationRequest, "admin", "uaa");

            CompositeToken accessToken = (CompositeToken) tokenServices.createAccessToken(auth2Authentication);

            Jwt jwtToken = JwtHelper.decode(accessToken.getIdTokenValue());
            assertThat(jwtToken.getHeader().getJku(), startsWith(uaaUrl));
            assertThat(jwtToken.getHeader().getJku(), is("https://uaa.some.test.domain.com:555/uaa/token_keys"));
        }

        @ParameterizedTest
        @ValueSource(strings = {GRANT_TYPE_PASSWORD, GRANT_TYPE_AUTHORIZATION_CODE, GRANT_TYPE_IMPLICIT})
        public void ensureIdTokenReturned_whenClientHasOpenIdScope_andOpenIdScopeIsRequested_andIdTokenResponseType_withGrantType(String grantType) {
            AuthorizationRequest authorizationRequest = constructAuthorizationRequest(grantType, requestedScope);
            authorizationRequest.setResponseTypes(Sets.newHashSet(responseType));

            OAuth2Authentication auth2Authentication = constructUserAuthenticationFromAuthzRequest(authorizationRequest, "admin", "uaa");

            CompositeToken accessToken = (CompositeToken) tokenServices.createAccessToken(auth2Authentication);

            assertThat(accessToken.getIdTokenValue(), is(not(nullValue())));
            JwtHelper.decode(accessToken.getIdTokenValue());
        }
    }

    @Test
    public void ensureJKUHeaderIsSetWhenBuildingAnAccessToken() {
        AuthorizationRequest authorizationRequest = constructAuthorizationRequest(GRANT_TYPE_CLIENT_CREDENTIALS, Strings.split(clientScopes, ','));

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        Jwt decode = JwtHelper.decode(accessToken.getValue());
        assertThat(decode.getHeader().getJku(), startsWith(uaaUrl));
        assertThat(decode.getHeader().getJku(), is("https://uaa.some.test.domain.com:555/uaa/token_keys"));
    }


    @Test
    public void ensureJKUHeaderIsSetWhenBuildingARefreshToken() {
        AuthorizationRequest authorizationRequest = constructAuthorizationRequest(GRANT_TYPE_PASSWORD, "oauth.approvals");

        OAuth2Authentication auth2Authentication = constructUserAuthenticationFromAuthzRequest(authorizationRequest, "admin", "uaa");

        CompositeToken accessToken = (CompositeToken) tokenServices.createAccessToken(auth2Authentication);

        Jwt jwtToken = JwtHelper.decode(accessToken.getRefreshToken().getValue());
        assertThat(jwtToken.getHeader().getJku(), startsWith(uaaUrl));
        assertThat(jwtToken.getHeader().getJku(), is("https://uaa.some.test.domain.com:555/uaa/token_keys"));
    }


    private OAuth2Authentication constructUserAuthenticationFromAuthzRequest(AuthorizationRequest authzRequest,
                                                                             String userId,
                                                                             String userOrigin,
                                                                             GrantedAuthority... authorities
    ) {
        UaaUser uaaUser = jdbcUaaUserDatabase.retrieveUserByName(userId, userOrigin);
        UaaPrincipal principal = new UaaPrincipal(uaaUser);
        UaaAuthentication userAuthentication = new UaaAuthentication(
          principal, null, Arrays.asList(authorities), null, true, System.currentTimeMillis()
        );
        return new OAuth2Authentication(authzRequest.createOAuth2Request(), userAuthentication);
    }

    private AuthorizationRequest constructAuthorizationRequest(String grantType, String... scopes) {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(clientId, Arrays.asList(scopes));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, grantType);
        authorizationRequest.setRequestParameters(azParameters);
        return authorizationRequest;
    }
}