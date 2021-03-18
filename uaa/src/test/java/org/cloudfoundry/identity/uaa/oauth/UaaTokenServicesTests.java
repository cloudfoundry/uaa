package org.cloudfoundry.identity.uaa.oauth;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.bouncycastle.util.Strings;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
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
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.joda.time.DateTime;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import java.util.ArrayList;
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
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasKey;
import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@DisplayName("Uaa Token Services Tests")
@DefaultTestContext
@TestPropertySource(properties = {"uaa.url=https://uaa.some.test.domain.com:555/uaa"})
class UaaTokenServicesTests {
    @Autowired
    private UaaTokenServices tokenServices;

    private String clientId = "jku_test";
    private String clientSecret = "secret";
    private String clientScopes = "openid,oauth.approvals,user_attributes";

    @Autowired
    private JdbcUaaUserDatabase jdbcUaaUserDatabase;
    @Autowired
    private MultitenantClientServices jdbcClientDetailsService;

    @Nested
    @DisplayName("when building an id token")
    @DefaultTestContext
    @TestPropertySource(properties = {"uaa.url=https://uaa.some.test.domain.com:555/uaa"})
    class WhenRequestingAnIdToken {
        private String requestedScope;

        @BeforeEach
        void setupRequest() throws InterruptedException {
            requestedScope = "openid";
            assumeTrue(waitForClient(clientId, 3), "Test client jku_test not up yet");
        }

        @DisplayName("id token should contain jku header")
        @Test
        void ensureJKUHeaderIsSetWhenBuildingAnIdToken() {
            AuthorizationRequest authorizationRequest = constructAuthorizationRequest(clientId, GRANT_TYPE_PASSWORD, requestedScope);

            OAuth2Authentication auth2Authentication = constructUserAuthenticationFromAuthzRequest(authorizationRequest, "admin", "uaa");

            CompositeToken accessToken = (CompositeToken) tokenServices.createAccessToken(auth2Authentication);

            Jwt jwtToken = JwtHelper.decode(accessToken.getIdTokenValue());
            assertThat(jwtToken.getHeader().getJku(), is("https://uaa.some.test.domain.com:555/uaa/token_keys"));
        }

        @DisplayName("ensureIdToken Returned when Client Has OpenId Scope and Scope=OpenId withGrantType")
        @ParameterizedTest
        @ValueSource(strings = {GRANT_TYPE_PASSWORD, GRANT_TYPE_AUTHORIZATION_CODE, GRANT_TYPE_IMPLICIT})
        void ensureIdTokenReturned_withGrantType(String grantType) {
            AuthorizationRequest authorizationRequest = constructAuthorizationRequest(clientId, grantType, requestedScope);

            OAuth2Authentication auth2Authentication = constructUserAuthenticationFromAuthzRequest(authorizationRequest, "admin", "uaa");

            CompositeToken accessToken = (CompositeToken) tokenServices.createAccessToken(auth2Authentication);

            assertThat(accessToken.getIdTokenValue(), is(not(nullValue())));
            JwtHelper.decode(accessToken.getIdTokenValue());
        }

        @Nested
        @DisplayName("when the user doesn't request the 'openid' scope")
        @DefaultTestContext
        @TestPropertySource(properties = {"uaa.url=https://uaa.some.test.domain.com:555/uaa"})
        class WhenUserDoesntRequestOpenIdScope {
            private List<String> logEvents = new ArrayList<>();
            private AbstractAppender appender;

            @BeforeEach
            void addLoggerAppender() {
                appender = new AbstractAppender("", null, null) {
                    @Override
                    public void append(LogEvent event) {
                        logEvents.add(event.getMessage().getFormattedMessage());
                    }
                };
                appender.start();

                LoggerContext context = (LoggerContext) LogManager.getContext(false);
                context.getRootLogger().addAppender(appender);
            }

            @AfterEach
            void removeAppender() {
                LoggerContext context = (LoggerContext) LogManager.getContext(false);
                context.getRootLogger().removeAppender(appender);
            }

            @BeforeEach
            void setupRequest() {
                requestedScope = "uaa.admin";
            }

            @DisplayName("id token should not be returned")
            @ParameterizedTest
            @ValueSource(strings = {GRANT_TYPE_PASSWORD, GRANT_TYPE_AUTHORIZATION_CODE, GRANT_TYPE_IMPLICIT})
            void ensureAnIdTokenIsNotReturned(String grantType) {
                AuthorizationRequest authorizationRequest = constructAuthorizationRequest(clientId, grantType, requestedScope);

                OAuth2Authentication auth2Authentication = constructUserAuthenticationFromAuthzRequest(authorizationRequest, "admin", "uaa");

                CompositeToken accessToken = (CompositeToken) tokenServices.createAccessToken(auth2Authentication);
                assertAll("id token is not returned, and a useful log message is printed",
                        () -> assertThat(accessToken.getIdTokenValue(), is(nullValue())),
                        () -> assertThat("Useful log message", logEvents, hasItem("an ID token was requested but 'openid' is missing from the requested scopes"))
                );
            }
        }

        @Nested
        @DisplayName("when the hasn't approved the 'openid' scope")
        @DefaultTestContext
        @TestPropertySource(properties = {"uaa.url=https://uaa.some.test.domain.com:555/uaa"})
        class WhenUserHasNotApprovedOpenIdScope {

            @Autowired
            private JdbcApprovalStore jdbcApprovalStore;

            @BeforeEach
            void setupRequest() {
                clientId = "jku_test_without_autoapprove";

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
            void ensureAnIdTokenIsNotReturned(String grantType) {
                AuthorizationRequest authorizationRequest = constructAuthorizationRequest(clientId, grantType, requestedScope);

                OAuth2Authentication auth2Authentication = constructUserAuthenticationFromAuthzRequest(authorizationRequest, "admin", "uaa");

                CompositeToken accessToken = (CompositeToken) tokenServices.createAccessToken(auth2Authentication);
                assertThat(accessToken.getIdTokenValue(), is(nullValue()));
            }

            @DisplayName("id token should returned when grant type is password")
            @Test
            void ensureAnIdTokenIsReturned() {
                AuthorizationRequest authorizationRequest = constructAuthorizationRequest(clientId, GRANT_TYPE_PASSWORD, requestedScope);

                OAuth2Authentication auth2Authentication = constructUserAuthenticationFromAuthzRequest(authorizationRequest, "admin", "uaa");

                CompositeToken accessToken = (CompositeToken) tokenServices.createAccessToken(auth2Authentication);
                assertThat(accessToken.getIdTokenValue(), is(not(nullValue())));
            }
        }
    }

    @Test
    void ensureJKUHeaderIsSetWhenBuildingAnAccessToken() {
        AuthorizationRequest authorizationRequest = constructAuthorizationRequest(clientId, GRANT_TYPE_CLIENT_CREDENTIALS, Strings.split(clientScopes, ','));

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        Jwt decode = JwtHelper.decode(accessToken.getValue());
        assertThat(decode.getHeader().getJku(), is("https://uaa.some.test.domain.com:555/uaa/token_keys"));
    }

    @Test
    void ensureJKUHeaderIsSetWhenBuildingARefreshToken() {
        AuthorizationRequest authorizationRequest = constructAuthorizationRequest(clientId, GRANT_TYPE_PASSWORD, "oauth.approvals");

        OAuth2Authentication auth2Authentication = constructUserAuthenticationFromAuthzRequest(authorizationRequest, "admin", "uaa");

        CompositeToken accessToken = (CompositeToken) tokenServices.createAccessToken(auth2Authentication);

        Jwt jwtToken = JwtHelper.decode(accessToken.getRefreshToken().getValue());
        assertThat(jwtToken.getHeader().getJku(), is("https://uaa.some.test.domain.com:555/uaa/token_keys"));
    }

    @Nested
    @DisplayName("when performing the refresh grant type")
    @DefaultTestContext
    @TestPropertySource(properties = {"uaa.url=https://uaa.some.test.domain.com:555/uaa"})
    @DirtiesContext
    class WhenRefreshGrant {
        @Autowired
        private RefreshTokenCreator refreshTokenCreator;

        private CompositeExpiringOAuth2RefreshToken refreshToken;

        @Test
        void happyCase() {
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
            OAuth2AccessToken refreshedToken = tokenServices.refreshAccessToken(this.refreshToken.getValue(), new TokenRequest(new HashMap<>(), "jku_test", Lists.newArrayList("openid", "user_attributes"), GRANT_TYPE_REFRESH_TOKEN));

            assertThat(refreshedToken, is(notNullValue()));
        }

        @Nested
        @DisplayName("when ACR claim is present")
        @DefaultTestContext
        @TestPropertySource(properties = {"uaa.url=https://uaa.some.test.domain.com:555/uaa"})
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
            void happyCase(List<String> acrs) {
                setup(new HashSet<>(acrs));
                assumeTrue(waitForClient("jku_test", 5), "Test client needs to be setup for this test");
                CompositeToken refreshedToken = (CompositeToken) tokenServices.refreshAccessToken(
                        refreshToken.getValue(),
                        new TokenRequest(
                                Maps.newHashMap(), "jku_test", Lists.newArrayList("openid", "user_attributes"), GRANT_TYPE_REFRESH_TOKEN
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
        @DisplayName("when 'openid' scope was not requested in original token grant")
        @DefaultTestContext
        @TestPropertySource(properties = {"uaa.url=https://uaa.some.test.domain.com:555/uaa"})
        class WhenOpenIdScopeNotRequested {
            @ParameterizedTest
            @ValueSource(strings = {GRANT_TYPE_PASSWORD, GRANT_TYPE_AUTHORIZATION_CODE})
            @DisplayName("an ID token is not returned")
            void idTokenNotReturned(String grantType) {
                String nonOpenIdScope = "user_attributes";
                AuthorizationRequest authorizationRequest = constructAuthorizationRequest(clientId, grantType, nonOpenIdScope);
                OAuth2Authentication auth2Authentication = constructUserAuthenticationFromAuthzRequest(authorizationRequest, "admin", "uaa");
                CompositeToken compositeToken = (CompositeToken) tokenServices.createAccessToken(auth2Authentication);

                CompositeToken refreshedToken = (CompositeToken) tokenServices.refreshAccessToken(
                        compositeToken.getRefreshToken().getValue(),
                        new TokenRequest(
                                Maps.newHashMap(), "jku_test", null, GRANT_TYPE_REFRESH_TOKEN
                        )
                );

                assertThat(refreshedToken.getIdTokenValue(), is(nullValue()));
            }
        }

        @Nested
        @DisplayName("when client does not have 'openid' scope")
        @DefaultTestContext
        @TestPropertySource(properties = {"uaa.url=https://uaa.some.test.domain.com:555/uaa"})
        class WhenClientDoesNotHaveOpenIdScope {
            @ParameterizedTest
            @ValueSource(strings = {GRANT_TYPE_PASSWORD, GRANT_TYPE_AUTHORIZATION_CODE})
            @DisplayName("an ID token is not returned")
            void idTokenNotReturned(String grantType) {
                String nonOpenIdScope = "password.write";
                assumeTrue(waitForClient("client_without_openid", 5), "Test client needs to be setup for this test");
                AuthorizationRequest authorizationRequest = constructAuthorizationRequest("client_without_openid", grantType, nonOpenIdScope);
                OAuth2Authentication auth2Authentication = constructUserAuthenticationFromAuthzRequest(authorizationRequest, "admin", "uaa");
                CompositeToken compositeToken = (CompositeToken) tokenServices.createAccessToken(auth2Authentication);
                assertThat(compositeToken.getIdTokenValue(), is(nullValue()));

                CompositeToken refreshedToken = (CompositeToken) tokenServices.refreshAccessToken(
                        compositeToken.getRefreshToken().getValue(),
                        new TokenRequest(
                                Maps.newHashMap(), "client_without_openid", null, GRANT_TYPE_REFRESH_TOKEN
                        )
                );

                assertThat(refreshedToken.getIdTokenValue(), is(nullValue()));
            }
        }

        @Nested
        @DisplayName("when scoping down the refresh token to exclude 'openid' scope")
        @DefaultTestContext
        @TestPropertySource(properties = {"uaa.url=https://uaa.some.test.domain.com:555/uaa"})
        class WhenScopingDownToExcludeOpenIdScope {
            @ParameterizedTest
            @ValueSource(strings = {GRANT_TYPE_PASSWORD, GRANT_TYPE_AUTHORIZATION_CODE})
            @DisplayName("an ID token is not returned")
            void idTokenNotReturned(String grantType) {
                AuthorizationRequest authorizationRequest = constructAuthorizationRequest("jku_test", grantType, "openid", "user_attributes");
                OAuth2Authentication auth2Authentication = constructUserAuthenticationFromAuthzRequest(authorizationRequest, "admin", "uaa");
                CompositeToken compositeToken = (CompositeToken) tokenServices.createAccessToken(auth2Authentication);
                assertThat(compositeToken.getIdTokenValue(), is(not(nullValue())));

                CompositeToken refreshedToken = (CompositeToken) tokenServices.refreshAccessToken(
                        compositeToken.getRefreshToken().getValue(),
                        new TokenRequest(
                                Maps.newHashMap(), "jku_test", Sets.newHashSet("user_attributes"), GRANT_TYPE_REFRESH_TOKEN
                        )
                );

                assertThat(refreshedToken.getIdTokenValue(), is(nullValue()));
            }
        }

        @Nested
        @DisplayName("when AMR claim is present")
        @DefaultTestContext
        @TestPropertySource(properties = {"uaa.url=https://uaa.some.test.domain.com:555/uaa"})
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
            void happyCase(List<String> amrs) {
                setup(amrs);

                CompositeToken refreshedToken = (CompositeToken) tokenServices.refreshAccessToken(
                        refreshToken.getValue(),
                        new TokenRequest(
                                Maps.newHashMap(), "jku_test", Lists.newArrayList("openid", "user_attributes"), GRANT_TYPE_REFRESH_TOKEN
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

    private AuthorizationRequest constructAuthorizationRequest(String clientId, String grantType, String... scopes) {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(clientId, Arrays.asList(scopes));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, grantType);
        authorizationRequest.setRequestParameters(azParameters);
        return authorizationRequest;
    }

    private boolean waitForClient(String clientId, int max) {
        int retry = 0;
        while(retry++ < max) {
            try {
                jdbcClientDetailsService.loadClientByClientId(clientId);
                return true;
            } catch (NoSuchClientException e) {
                try {
                    Thread.sleep(500);
                } catch (InterruptedException interruptedException) {
                    return false;
                }
            }
        }
        return false;
    }
}
