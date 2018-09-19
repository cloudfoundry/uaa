package org.cloudfoundry.identity.uaa.oauth;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import org.apache.commons.io.output.TeeOutputStream;
import org.bouncycastle.util.Strings;
import org.cloudfoundry.identity.uaa.annotations.WithSpring;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.JdbcApprovalStore;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.refresh.CompositeExpiringOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.refresh.RefreshTokenCreator;
import org.cloudfoundry.identity.uaa.oauth.refresh.RefreshTokenRequestData;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeToken;
import org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.hamcrest.CoreMatchers;
import org.joda.time.DateTime;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_IMPLICIT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

@WithSpring
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
    @WithSpring
    class WhenRequestingAnIdToken {
        private String requestedScope;
        private String responseType;

        private PrintStream systemOut;
        private PrintStream systemErr;
        private ByteArrayOutputStream loggingOutputStream;

        @BeforeEach
        void setupLogger() {
            systemOut = System.out;
            systemErr = System.err;

            loggingOutputStream = new ByteArrayOutputStream();

            System.setErr(new PrintStream(new TeeOutputStream(loggingOutputStream, systemOut), true));
            System.setOut(new PrintStream(new TeeOutputStream(loggingOutputStream, systemErr), true));
        }

        @AfterEach
        void resetStdout() {
            System.setOut(systemOut);
            System.setErr(systemErr);
        }


        @BeforeEach
        void setupRequest() {
            requestedScope = "openid";
            responseType = "id_token";
        }

        @Tag("oidc spec")
        @DisplayName("id token should contain jku header")
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

        @Tag("oidc spec")
        @Tag("uaa oidc logic")
        @DisplayName("ensureIdToken Returned when Client Has OpenId Scope and Scope=OpenId, ResponseType=id_token withGrantType")
        @ParameterizedTest
        @ValueSource(strings = {GRANT_TYPE_PASSWORD, GRANT_TYPE_AUTHORIZATION_CODE, GRANT_TYPE_IMPLICIT})
        public void ensureIdTokenReturned_withGrantType(String grantType) {
            AuthorizationRequest authorizationRequest = constructAuthorizationRequest(grantType, requestedScope);
            authorizationRequest.setResponseTypes(Sets.newHashSet(responseType));

            OAuth2Authentication auth2Authentication = constructUserAuthenticationFromAuthzRequest(authorizationRequest, "admin", "uaa");

            CompositeToken accessToken = (CompositeToken) tokenServices.createAccessToken(auth2Authentication);

            assertThat(accessToken.getIdTokenValue(), is(not(nullValue())));
            JwtHelper.decode(accessToken.getIdTokenValue());
        }

        @Tag("oidc spec")
        @Tag("uaa oidc logic")
        @Nested
        @DisplayName("when the user doesn't request the 'openid' scope")
        @WithSpring
        class WhenUserDoesntRequestOpenIdScope {
            @BeforeEach
            void setupRequest() {
                requestedScope = "uaa.admin";
            }

            @DisplayName("id token should not be returned")
            @ParameterizedTest
            @ValueSource(strings = {GRANT_TYPE_PASSWORD, GRANT_TYPE_AUTHORIZATION_CODE, GRANT_TYPE_IMPLICIT})
            public void ensureAnIdTokenIsNotReturned(String grantType) {
                AuthorizationRequest authorizationRequest = constructAuthorizationRequest(grantType, requestedScope);
                authorizationRequest.setResponseTypes(Sets.newHashSet(responseType));

                OAuth2Authentication auth2Authentication = constructUserAuthenticationFromAuthzRequest(authorizationRequest, "admin", "uaa");

                CompositeToken accessToken = (CompositeToken) tokenServices.createAccessToken(auth2Authentication);
                assertAll("id token is not returned, and a useful log message is printed",
                  () -> assertThat(accessToken.getIdTokenValue(), is(nullValue())),
                  () -> assertThat("Useful log message", loggingOutputStream.toString(), containsString("an ID token was requested but 'openid' is missing from the requested scopes")),
                  () -> assertThat("Does not contain log message", loggingOutputStream.toString(), not(containsString("an ID token cannot be returned since the user didn't specify 'id_token' as the response_type")))
                );
            }
        }


        @Nested
        @DisplayName("when the hasn't approved the 'openid' scope")
        @WithSpring
        class WhenUserHasNotApproviedOpenIdScope {

            @Value("${oauth.clients.jku_test_without_autoapprove.id}")
            private String clientWithoutAutoApprove;

            @Value("${oauth.clients.jku_test_without_autoapprove.secret}")
            private String clientWithoutAutoApproveSecret;

            @Autowired
            private JdbcApprovalStore jdbcApprovalStore;

            @BeforeEach
            void setupRequest() {
                clientId = clientWithoutAutoApprove;
                clientSecret = clientWithoutAutoApprove;

                Approval approvedNonOpenIdScope = new Approval().setUserId("admin").setScope("oauth.approvals").setClientId(clientId).setExpiresAt(DateTime.now().plusDays(1).toDate()).setStatus(Approval.ApprovalStatus.APPROVED);
                jdbcApprovalStore.addApproval(approvedNonOpenIdScope, "uaa");
            }

            @AfterEach
            void resetUserApproval() {
                jdbcApprovalStore.deleteByUser("admin", "uaa");
            }

            @DisplayName("id token should not be returned")
            @ParameterizedTest
            @ValueSource(strings = {GRANT_TYPE_AUTHORIZATION_CODE, GRANT_TYPE_IMPLICIT})
            public void ensureAnIdTokenIsNotReturned(String grantType) {
                AuthorizationRequest authorizationRequest = constructAuthorizationRequest(grantType, requestedScope);
                authorizationRequest.setResponseTypes(Sets.newHashSet(responseType));

                OAuth2Authentication auth2Authentication = constructUserAuthenticationFromAuthzRequest(authorizationRequest, "admin", "uaa");

                CompositeToken accessToken = (CompositeToken) tokenServices.createAccessToken(auth2Authentication);
                assertThat(accessToken.getIdTokenValue(), is(nullValue()));
            }

            @DisplayName("id token should returned when grant type is password")
            @Test
            public void ensureAnIdTokenIsReturned() {
                AuthorizationRequest authorizationRequest = constructAuthorizationRequest(GRANT_TYPE_PASSWORD, requestedScope);
                authorizationRequest.setResponseTypes(Sets.newHashSet(responseType));

                OAuth2Authentication auth2Authentication = constructUserAuthenticationFromAuthzRequest(authorizationRequest, "admin", "uaa");

                CompositeToken accessToken = (CompositeToken) tokenServices.createAccessToken(auth2Authentication);
                assertThat(accessToken.getIdTokenValue(), is(not(nullValue())));
            }
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

    @Nested
    @DisplayName("when performing the refresh grant type")
    @WithSpring
    class WhenRefreshGrant {
        @Autowired
        private RefreshTokenCreator refreshTokenCreator;

        private CompositeExpiringOAuth2RefreshToken refreshToken;

        @BeforeEach
        void setup() {
            RefreshTokenRequestData refreshTokenRequestData = new RefreshTokenRequestData(
              GRANT_TYPE_AUTHORIZATION_CODE,
              Sets.newHashSet("openid", "user_attributes"),
              null,
              "",
              Sets.newHashSet(""),
              "jku_test",
              false,
              new Date(),
              null,
              null
            );
            UaaUser uaaUser = jdbcUaaUserDatabase.retrieveUserByName("admin", "uaa");
            refreshToken = refreshTokenCreator.createRefreshToken(uaaUser, refreshTokenRequestData, null);
            assertThat(refreshToken, is(notNullValue()));
        }

        @Test
        public void happyCase() {
            OAuth2AccessToken refreshedToken = tokenServices.refreshAccessToken(this.refreshToken.getValue(), new TokenRequest(new HashMap<>(), "jku_test", Lists.newArrayList("openid", "user_attributes"), GRANT_TYPE_REFRESH_TOKEN));

            assertThat(refreshedToken, is(notNullValue()));
        }

        @Nested
        @DisplayName("when ACR claim is present")
        @WithSpring
        class WhenAcrClaimIsPresent {

            void setup(Set<String> acrs) {
                RefreshTokenRequestData refreshTokenRequestData = new RefreshTokenRequestData(
                  GRANT_TYPE_AUTHORIZATION_CODE,
                  Sets.newHashSet("openid", "user_attributes"),
                  null,
                  "",
                  Sets.newHashSet(""),
                  "jku_test",
                  false,
                  new Date(),
                  acrs,
                  null
                );
                UaaUser uaaUser = jdbcUaaUserDatabase.retrieveUserByName("admin", "uaa");
                refreshToken = refreshTokenCreator.createRefreshToken(uaaUser, refreshTokenRequestData, null);
                assertThat(refreshToken, is(notNullValue()));
            }

            @ParameterizedTest
            @MethodSource("org.cloudfoundry.identity.uaa.oauth.UaaTokenServicesTests#authenticationTestParams")
            @DisplayName("an ID token is returned with ACR claim")
            public void happyCase(List<String> acrs) {
                setup(new HashSet<>(acrs));

                HashMap<String, String> tokenRequestParams = new HashMap<String, String>() {{
                    put("response_type", "id_token");
                }};
                CompositeToken refreshedToken = (CompositeToken) tokenServices.refreshAccessToken(
                  refreshToken.getValue(),
                  new TokenRequest(
                    tokenRequestParams, "jku_test", Lists.newArrayList("openid", "user_attributes"), GRANT_TYPE_REFRESH_TOKEN
                  )
                );

                assertThat(refreshedToken, is(notNullValue()));

                Map<String, Object> claims = UaaTokenUtils.getClaims(refreshedToken.getIdTokenValue());
                assertThat(claims.size(), greaterThan(0));
                assertThat(claims, hasKey(ClaimConstants.ACR));
                assertThat(claims.get(ClaimConstants.ACR), notNullValue());
                assertThat((Map<String, Object>) claims.get(ClaimConstants.ACR), hasKey("values"));
                List<String> values = (List<String>) ((Map<String, Object>) claims.get(ClaimConstants.ACR)).get("values");
                assertThat(values, notNullValue());
                assertThat(values, containsInAnyOrder(acrs.toArray()));
            }
        }

        @Nested
        @DisplayName("when AMR claim is present")
        @WithSpring
        class WhenAmrClaimIsPresent {

            public void setup(List<String> amrs) {
                RefreshTokenRequestData refreshTokenRequestData = new RefreshTokenRequestData(
                  GRANT_TYPE_AUTHORIZATION_CODE,
                  Sets.newHashSet("openid", "user_attributes"),
                  Sets.newHashSet(amrs),
                  null,
                  Sets.newHashSet(""),
                  "jku_test",
                  false,
                  new Date(),
                  null,
                  null
                );
                UaaUser uaaUser = jdbcUaaUserDatabase.retrieveUserByName("admin", "uaa");
                refreshToken = refreshTokenCreator.createRefreshToken(uaaUser, refreshTokenRequestData, null);
                assertThat(refreshToken, is(notNullValue()));
            }

            @DisplayName("an ID token is returned with AMR claim")
            @ParameterizedTest
            @MethodSource("org.cloudfoundry.identity.uaa.oauth.UaaTokenServicesTests#authenticationTestParams")
            public void happyCase(List<String> amrs) {
                setup(amrs);

                HashMap<String, String> tokenRequestParams = new HashMap<String, String>() {{
                    put("response_type", "id_token");
                }};
                CompositeToken refreshedToken = (CompositeToken) tokenServices.refreshAccessToken(
                  refreshToken.getValue(),
                  new TokenRequest(
                    tokenRequestParams, "jku_test", Lists.newArrayList("openid", "user_attributes"), GRANT_TYPE_REFRESH_TOKEN
                  )
                );

                assertThat(refreshedToken, is(notNullValue()));

                Map<String, Object> claims = UaaTokenUtils.getClaims(refreshedToken.getIdTokenValue());
                assertThat(claims.size(), greaterThan(0));
                assertThat(claims, hasKey(ClaimConstants.AMR));
                assertThat(claims.get(ClaimConstants.AMR), notNullValue());
                List<String> actualAmrs = (List<String>) claims.get(ClaimConstants.AMR);
                assertThat(actualAmrs, containsInAnyOrder(amrs.toArray()));
            }
        }
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

    static Stream<List<String>> authenticationTestParams() {
        List<String> validAcrs = Lists.newArrayList("val1", "val2");
        List<String> nullAcrs = Lists.newArrayList((String) null);
        List<String> validAcrsWithNull = Lists.newArrayList("val1", null, "val2");
        List<String> intAcrs = Lists.newArrayList("2");

        return Stream.of(
          validAcrs,
          nullAcrs,
          validAcrsWithNull,
          intAcrs
        );

    }
    private AuthorizationRequest constructAuthorizationRequest(String grantType, String... scopes) {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(clientId, Arrays.asList(scopes));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, grantType);
        authorizationRequest.setRequestParameters(azParameters);
        return authorizationRequest;
    }
}