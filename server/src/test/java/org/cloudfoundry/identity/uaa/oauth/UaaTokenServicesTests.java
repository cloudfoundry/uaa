/*******************************************************************************
*     Cloud Foundry
*     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
*
*     This product is licensed to you under the Apache License, Version 2.0 (the "License").
*     You may not use this product except in compliance with the License.
*
*     This product includes a number of subcomponents with
*     separate copyright notices and license terms. Your use of these
*     subcomponents is subject to the terms and conditions of the
*     subcomponent's license, as noted in the LICENSE file.
*******************************************************************************/
package org.cloudfoundry.identity.uaa.oauth;

import org.apache.commons.collections.map.HashedMap;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.TokenIssuedEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.approval.InMemoryApprovalStore;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeAccessToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.oauth.token.matchers.AbstractOAuth2AccessTokenMatchers;
import org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2RefreshTokenMatchers;
import org.cloudfoundry.identity.uaa.test.MockAuthentication;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventPublisher;
import org.cloudfoundry.identity.uaa.user.InMemoryUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.stubbing.Answer;
import org.opensaml.saml2.core.AuthnContext;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Field;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Collections.EMPTY_SET;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singleton;
import static org.cloudfoundry.identity.uaa.oauth.UaaTokenServices.UAA_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification.SECRET;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.OPAQUE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.REQUEST_TOKEN_FORMAT;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.audience;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.cid;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.clientId;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.email;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.expiry;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.issuedAt;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.issuerUri;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.jwtId;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.origin;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.revocationSignature;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.scope;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.subject;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.userId;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.username;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.validFor;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.zoneId;
import static org.cloudfoundry.identity.uaa.user.UaaAuthority.USER_AUTHORITIES;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.core.AllOf.allOf;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.hamcrest.number.OrderingComparison.lessThanOrEqualTo;
import static org.hamcrest.text.IsEmptyString.isEmptyString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Parameterized.class)
public class UaaTokenServicesTests {

    public static final String CLIENT_ID = "client";
    public static final String GRANT_TYPE = "grant_type";
    public static final String PASSWORD = "password";
    public static final String CLIENT_CREDENTIALS = "client_credentials";
    public static final String AUTHORIZATION_CODE = "authorization_code";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String IMPLICIT = "implicit";
    public static final String CLIENT_AUTHORITIES = "read,update,write,openid";
    public static final String ISSUER_URI = "http://localhost:8080/uaa/oauth/token";
    public static final String READ = "read";
    public static final String WRITE = "write";
    public static final String DELETE = "delete";
    public static final String ALL_GRANTS_CSV = "authorization_code,password,implicit,client_credentials";
    public static final String CLIENTS = "clients";
    public static final String SCIM = "scim";
    public static final String OPENID = "openid";
    public static final String ROLES = "roles";
    public static final String PROFILE = "profile";


    private TestApplicationEventPublisher<TokenIssuedEvent> publisher;
    private UaaTokenServices tokenServices = new UaaTokenServices();

    private final int accessTokenValidity = 60 * 60 * 12;
    private final int refreshTokenValidity = 60 * 60 * 24 * 30;

    private List<GrantedAuthority> defaultUserAuthorities = Arrays.asList(
        UaaAuthority.authority("space.123.developer"),
        UaaAuthority.authority("uaa.user"),
        UaaAuthority.authority("space.345.developer"),
        UaaAuthority.authority("space.123.admin"),
        UaaAuthority.authority(OPENID),
        UaaAuthority.authority(READ),
        UaaAuthority.authority(WRITE),
        UaaAuthority.authority(UAA_REFRESH_TOKEN));

    private String userId = "12345";
    private String username = "jdsa";
    private String email = "jdsa@vmware.com";
    private final String externalId = "externalId";
    private UaaUser defaultUser =
        new UaaUser(
            new UaaUserPrototype()
            .withId(userId)
            .withUsername(username)
            .withPassword(PASSWORD)
            .withEmail(email)
            .withAuthorities(defaultUserAuthorities)
            .withGivenName("Marissa")
            .withFamilyName("Bloggs")
            .withPhoneNumber("1234567890")
            .withCreated(new Date(System.currentTimeMillis() - 15000))
            .withModified(new Date(System.currentTimeMillis() - 15000))
            .withOrigin(OriginKeys.UAA)
            .withExternalId(externalId)
            .withVerified(false)
            .withZoneId(IdentityZoneHolder.get().getId())
            .withSalt(userId)
            .withPasswordLastModified(new Date(System.currentTimeMillis() - 15000))
            .withLastLogonSuccess(12345L)
        );


    // Need to create a user with a modified time slightly in the past because
    // the token IAT is in seconds and the token
    // expiry
    // skew will not be long enough
    private InMemoryUaaUserDatabase userDatabase = new InMemoryUaaUserDatabase(singleton(defaultUser));

    private Authentication defaultUserAuthentication = new UsernamePasswordAuthenticationToken(new UaaPrincipal(defaultUser), "n/a", null);

    private InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();

    private ApprovalStore approvalStore = new InMemoryApprovalStore();
    private MockAuthentication mockAuthentication;
    private List<String> requestedAuthScopes;
    private List<String> clientScopes;
    private List<String> readScope;
    private List<String> writeScope;
    private List<String> expandedScopes;
    public List<String> resourceIds;
    private String expectedJson;
    private BaseClientDetails defaultClient;
    private OAuth2RequestFactory requestFactory;
    private TokenPolicy tokenPolicy;
    private RevocableTokenProvisioning tokenProvisioning;
    private final Map<String, RevocableToken> tokens = new HashMap<>();
    private Calendar expiresAt = Calendar.getInstance();
    private Calendar updatedAt = Calendar.getInstance();

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    private TestTokenEnhancer tokenEnhancer;

    public UaaTokenServicesTests(TestTokenEnhancer enhancer, String testname) {
        publisher = TestApplicationEventPublisher.forEventClass(TokenIssuedEvent.class);
        this.tokenEnhancer = enhancer;
    }

    @Parameterized.Parameters(name = "{index}: testname[{1}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {{null, "old behavior"}, {new TestTokenEnhancer(),"using enhancer"}});
    }


    @Before
    public void setUp() throws Exception {
        IdentityZoneHolder.clear();
        IdentityZoneProvisioning provisioning = mock(IdentityZoneProvisioning.class);
        IdentityZoneHolder.setProvisioning(provisioning);
        IdentityZone zone = IdentityZone.getUaa();
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        tokenPolicy = new TokenPolicy(accessTokenValidity, refreshTokenValidity);
        Map<String, String> keys = new HashMap<>();
        keys.put("testKey", "9c247h8yt978w3nv45y978w45hntv6");
        keys.put("otherKey", "unc0uf98gv89egh4v98749978hv");
        tokenPolicy.setKeys(keys);
        tokenPolicy.setActiveKeyId("testKey");
        config.setTokenPolicy(tokenPolicy);
        zone.setConfig(config);
        when(provisioning.retrieve("uaa")).thenReturn(zone);

        mockAuthentication = new MockAuthentication();
        SecurityContextHolder.getContext().setAuthentication(mockAuthentication);
        requestedAuthScopes = Arrays.asList(READ, WRITE,OPENID);
        clientScopes = Arrays.asList(READ, WRITE,OPENID);
        readScope = Arrays.asList(READ);
        writeScope = Arrays.asList(WRITE);
        expandedScopes = Arrays.asList(READ, WRITE, DELETE,OPENID);
        resourceIds = Arrays.asList(SCIM, CLIENTS);
        expectedJson = "[\""+READ+"\",\""+WRITE+"\",\""+OPENID+"\"]";


        defaultClient = new BaseClientDetails(
            CLIENT_ID,
            SCIM+","+CLIENTS,
            READ+","+WRITE+","+OPENID+","+UAA_REFRESH_TOKEN,
            ALL_GRANTS_CSV,
            CLIENT_AUTHORITIES);

        clientDetailsService.setClientDetailsStore(
            Collections.singletonMap(
                CLIENT_ID,
                defaultClient
            )
        );

        tokenProvisioning = mock(RevocableTokenProvisioning.class);
        when(tokenProvisioning.create(anyObject())).thenAnswer((Answer<RevocableToken>) invocation -> {
            RevocableToken arg = (RevocableToken)invocation.getArguments()[0];
            tokens.put(arg.getTokenId(), arg);
            return arg;
        });
        when(tokenProvisioning.update(anyString(), anyObject())).thenAnswer((Answer<RevocableToken>) invocation -> {
            String id = (String)invocation.getArguments()[0];
            RevocableToken arg = (RevocableToken)invocation.getArguments()[1];
            arg.setTokenId(id);
            tokens.put(arg.getTokenId(), arg);
            return arg;
        });
        when(tokenProvisioning.retrieve(anyString())).thenAnswer((Answer<RevocableToken>) invocation -> {
            String id = (String)invocation.getArguments()[0];
            RevocableToken result = tokens.get(id);
            if (result==null) {
                throw new EmptyResultDataAccessException(1);
            }
            return result;

        });

        AbstractOAuth2AccessTokenMatchers.revocableTokens.set(tokens);

        requestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);
        tokenServices.setClientDetailsService(clientDetailsService);
        tokenServices.setTokenPolicy(tokenPolicy);
        tokenServices.setDefaultUserAuthorities(AuthorityUtils.authorityListToSet(USER_AUTHORITIES));
        tokenServices.setIssuer("http://localhost:8080/uaa");
        tokenServices.setUserDatabase(userDatabase);
        tokenServices.setApprovalStore(approvalStore);
        tokenServices.setApplicationEventPublisher(publisher);
        tokenServices.setTokenProvisioning(tokenProvisioning);
        tokenServices.setUaaTokenEnhancer(tokenEnhancer);
        tokenServices.afterPropertiesSet();
    }

    @After
    public void teardown() {
        AbstractOAuth2AccessTokenMatchers.revocableTokens.remove();
        IdentityZoneHolder.clear();
        tokens.clear();
    }

    @Test
    public void null_issuer_should_fail() throws URISyntaxException {
        tokenServices = new UaaTokenServices();
        tokenServices.setClientDetailsService(mock(ClientDetailsService.class));
        try {
            tokenServices.afterPropertiesSet();
            fail();
        } catch (IllegalArgumentException x) {
            assertTrue(x.getMessage().contains("issuer must be set"));
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void do_not_allow_set_of_null_issuer() throws URISyntaxException {
        tokenServices.setIssuer(null);
    }

    @Test(expected = URISyntaxException.class)
    public void do_not_allow_set_of_non_url_issuer() throws URISyntaxException {
        tokenServices.setIssuer("some bla bla bla");
    }

    @Test(expected = IllegalArgumentException.class)
    public void getTokenEndpoint_Fails_If_Issuer_Is_Wrong() throws Exception {
        Field field = UaaTokenServices.class.getDeclaredField("issuer");
        field.setAccessible(true);
        ReflectionUtils.setField(field, tokenServices, "adasdas");
        tokenServices.getTokenEndpoint();
    }


    @Test
    public void is_opaque_token_required() {
        defaultClient.setAutoApproveScopes(singleton("true"));
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResponseTypes(new HashSet(Arrays.asList(CompositeAccessToken.ID_TOKEN, "token")));
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, TokenConstants.GRANT_TYPE_USER_TOKEN);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;
        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        assertTrue(tokenServices.opaqueTokenRequired(authentication));
    }

    @Test(expected = InvalidTokenException.class)
    public void testNullRefreshTokenString() {
        tokenServices.refreshAccessToken(null, null);
    }

    @Test(expected = InvalidGrantException.class)
    public void testInvalidGrantType() {
        AuthorizationRequest ar = mock(AuthorizationRequest.class);
        tokenServices.refreshAccessToken("", requestFactory.createTokenRequest(ar,"dsdada"));
    }

    @Test(expected = InvalidTokenException.class)
    public void testInvalidRefreshToken() {
        Map<String,String> map = new HashMap<>();
        map.put("grant_type", "refresh_token");
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(map,null,null,null,null,null,false,null,null,null);
        tokenServices.refreshAccessToken("dasdasdasdasdas", requestFactory.createTokenRequest(authorizationRequest, "refresh_token"));
    }

    @Test
    public void testCreateAccessTokenForAClient() {

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,clientScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, CLIENT_CREDENTIALS);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        assertCommonClientAccessTokenProperties(accessToken);
        assertThat(accessToken, validFor(is(accessTokenValidity)));
        assertThat(accessToken, issuerUri(is(ISSUER_URI)));
        assertThat(accessToken, zoneId(is(IdentityZoneHolder.get().getId())));
        assertThat(accessToken.getRefreshToken(), is(nullValue()));
        validateExternalAttributes(accessToken);

        assertCommonEventProperties(accessToken, CLIENT_ID, expectedJson);
    }


    @Test
    public void test_refresh_token_is_opaque_by_default() {
        OAuth2AccessToken accessToken = performPasswordGrant();
        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();

        String refreshTokenValue = accessToken.getRefreshToken().getValue();
        assertThat("Token value should be equal to or lesser than 36 characters", refreshTokenValue.length(), lessThanOrEqualTo(36));
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));
        TokenRequest refreshTokenRequest = getRefreshTokenRequest();

        //validate both opaque and JWT refresh tokens
        for (String s : Arrays.asList(refreshTokenValue, tokens.get(refreshTokenValue).getValue())) {
            OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(s, refreshTokenRequest);
            assertCommonUserAccessTokenProperties(refreshedAccessToken);
        }
    }

    @Test
    public void test_using_opaque_parameter_on_refresh_grant() {
        OAuth2AccessToken accessToken = performPasswordGrant();
        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        String refreshTokenValue = refreshToken.getValue();

        Map<String,String> parameters = new HashMap<>();
        parameters.put(REQUEST_TOKEN_FORMAT, OPAQUE);
        TokenRequest refreshTokenRequest = getRefreshTokenRequest(parameters);

        //validate both opaque and JWT refresh tokens
        for (String s : Arrays.asList(refreshTokenValue, tokens.get(refreshTokenValue).getValue())) {
            OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(s, refreshTokenRequest);
            assertThat("Token value should be equal to or lesser than 36 characters", refreshedAccessToken.getValue().length(), lessThanOrEqualTo(36));
            assertCommonUserAccessTokenProperties(new DefaultOAuth2AccessToken(tokens.get(refreshedAccessToken).getValue()));
        }
    }

    protected OAuth2AccessToken performPasswordGrant() {
        AuthorizationRequest authorizationRequest =  new AuthorizationRequest(CLIENT_ID, requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, PASSWORD);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        return tokenServices.createAccessToken(authentication);
    }

    @Test
    public void testCreateOpaqueAccessTokenForAClient() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, clientScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(REQUEST_TOKEN_FORMAT, TokenConstants.OPAQUE);
        azParameters.put(GRANT_TYPE, CLIENT_CREDENTIALS);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        assertTrue("Token is not a composite token", accessToken instanceof CompositeAccessToken);
        assertThat("Token value should be equal to or lesser than 36 characters", accessToken.getValue().length(), lessThanOrEqualTo(36));
        assertThat(accessToken.getRefreshToken(), is(nullValue()));
    }

    @Test
    public void testCreateAccessTokenForAClientInAnotherIdentityZone() {
        String subdomain = "test-zone-subdomain";
        IdentityZone identityZone = getIdentityZone(subdomain);
        identityZone.setConfig(
            JsonUtils.readValue(
                "{\"tokenPolicy\":{\"accessTokenValidity\":3600,\"refreshTokenValidity\":7200}}",
                IdentityZoneConfiguration.class
            )
        );
        IdentityZoneHolder.set(identityZone);
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,clientScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, CLIENT_CREDENTIALS);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonClientAccessTokenProperties(accessToken);
        assertThat(accessToken, validFor(is(3600)));
        assertThat(accessToken, issuerUri(is("http://"+subdomain+".localhost:8080/uaa/oauth/token")));
        assertThat(accessToken.getRefreshToken(), is(nullValue()));
        validateExternalAttributes(accessToken);

        Assert.assertEquals(1, publisher.getEventCount());

        this.assertCommonEventProperties(accessToken, CLIENT_ID, expectedJson);
    }

    private IdentityZone getIdentityZone(String subdomain) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setSubdomain(subdomain);
        identityZone.setName("The Twiglet Zone");
        identityZone.setDescription("Like the Twilight Zone but tastier.");
        return identityZone;
    }

    @Test
    public void testCreateAccessTokenAuthcodeGrant() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        validateAccessAndRefreshToken(accessToken);
    }

    @Test
    public void testCreateAccessTokenAuthcodeGrantSwitchedPrimaryKey() {
        String originalPrimaryKeyId = tokenPolicy.getActiveKeyId();
        try {
            tokenPolicy.setActiveKeyId("otherKey");

            AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
            authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
            Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
            azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
            authorizationRequest.setRequestParameters(azParameters);
            Authentication userAuthentication = defaultUserAuthentication;

            OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
            OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

            validateAccessAndRefreshToken(accessToken);
        } finally {
            tokenPolicy.setActiveKeyId(originalPrimaryKeyId);
        }
    }

    @Test
    public void testCreateAccessTokenPasswordGrant() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, PASSWORD);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        validateAccessAndRefreshToken(accessToken);
        tokenServices.loadAuthentication(accessToken.getValue());

        //ensure that we can load without user_name claim
        tokenServices.setExcludedClaims(new HashSet(Arrays.asList(ClaimConstants.AUTHORITIES, ClaimConstants.USER_NAME, ClaimConstants.EMAIL)));
        accessToken = tokenServices.createAccessToken(authentication);
        assertNotNull(tokenServices.loadAuthentication(accessToken.getValue()).getUserAuthentication());

    }


    @Test
    public void testClientSecret_Added_Token_Validation_Still_Works() {

        defaultClient.setClientSecret(SECRET);

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, PASSWORD);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        //normal token validation
        tokenServices.loadAuthentication(accessToken.getValue());

        //add a 2nd secret
        defaultClient.setClientSecret(defaultClient.getClientSecret()+" newsecret");
        tokenServices.loadAuthentication(accessToken.getValue());

        //generate a token when we have two secrets
        OAuth2AccessToken accessToken2 = tokenServices.createAccessToken(authentication);

        //remove the 1st secret
        defaultClient.setClientSecret("newsecret");
        try {
            tokenServices.loadAuthentication(accessToken.getValue());
            fail("Token should fail to validate on the revocation signature");
        } catch (InvalidTokenException e) {
            assertTrue(e.getMessage().contains("revocable signature mismatch"));
        }
        tokenServices.loadAuthentication(accessToken2.getValue());

        OAuth2AccessToken accessToken3 = tokenServices.createAccessToken(authentication);
        tokenServices.loadAuthentication(accessToken3.getValue());
    }

    @Test
    public void testCreateRevocableAccessTokenPasswordGrant() {
        OAuth2AccessToken accessToken = performPasswordGrant();

        validateAccessAndRefreshToken(accessToken);
    }

    protected void validateAccessAndRefreshToken(OAuth2AccessToken accessToken) {
        this.assertCommonUserAccessTokenProperties(accessToken);
        assertThat(accessToken, issuerUri(is(ISSUER_URI)));
        assertThat(accessToken, scope(is(requestedAuthScopes)));
        assertThat(accessToken, validFor(is(60 * 60 * 12)));
        validateExternalAttributes(accessToken);

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

        this.assertCommonEventProperties(accessToken, userId, buildJsonString(requestedAuthScopes));
    }

    protected void validateExternalAttributes(OAuth2AccessToken accessToken) {
        Map<String, String> extendedAttributes = (Map<String, String>) accessToken.getAdditionalInformation().get(ClaimConstants.EXTERNAL_ATTR);
        if (tokenEnhancer!=null) {
            Assert.assertEquals("test", extendedAttributes.get("purpose"));
        } else {
            assertNull("External attributes should not exist", extendedAttributes);
        }
    }

    @Test
    public void testCreateAccessTokenRefreshGrant() throws InterruptedException {
        OAuth2AccessToken accessToken = getOAuth2AccessToken();

        TokenRequest refreshTokenRequest = getRefreshTokenRequest();

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), refreshTokenRequest);

        assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken);
        assertThat(refreshedAccessToken, issuerUri(is(ISSUER_URI)));
        assertThat(refreshedAccessToken, scope(is(requestedAuthScopes)));
        assertThat(refreshedAccessToken, validFor(is(60 * 60 * 12)));
        validateExternalAttributes(accessToken);
    }

    protected TokenRequest getRefreshTokenRequest() {
        return getRefreshTokenRequest(emptyMap());
    }
    protected TokenRequest getRefreshTokenRequest(Map<String, String> requestParameters) {
        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        refreshAuthorizationRequest.setRequestParameters(requestParameters);
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);
        return requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token");
    }

    @Test
    public void createAccessToken_usingRefreshGrant_inOtherZone() throws Exception {
        String subdomain = "test-zone-subdomain";
        IdentityZone identityZone = getIdentityZone(subdomain);
        identityZone.setConfig(
            JsonUtils.readValue(
                "{\"tokenPolicy\":{\"accessTokenValidity\":3600,\"refreshTokenValidity\":9600}}",
                IdentityZoneConfiguration.class
            )
        );
        IdentityZoneHolder.set(identityZone);

        OAuth2AccessToken accessToken = getOAuth2AccessToken();

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
        assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken);
        assertThat(refreshedAccessToken, issuerUri(is("http://test-zone-subdomain.localhost:8080/uaa/oauth/token")));
        assertThat(refreshedAccessToken, scope(is(requestedAuthScopes)));
        assertThat(refreshedAccessToken, validFor(is(3600)));
        validateExternalAttributes(accessToken);
    }

    private OAuth2AccessToken getOAuth2AccessToken() {
        expiresAt.add(Calendar.MILLISECOND, 300000);
        updatedAt.add(Calendar.MILLISECOND, -1000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));
        approvalStore.addApproval(new Approval()
                                      .setUserId(userId)
                                      .setClientId(CLIENT_ID)
                                      .setScope(OPENID)
                                      .setExpiresAt(expiresAt.getTime())
                                      .setStatus(ApprovalStatus.APPROVED)
                                      .setLastUpdatedAt(updatedAt.getTime()));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        return tokenServices.createAccessToken(authentication);
    }

    @Test
    public void testCreateAccessTokenRefreshGrantAllScopesAutoApproved() throws InterruptedException {
        BaseClientDetails clientDetails = cloneClient(defaultClient);
        clientDetails.setAutoApproveScopes(singleton("true"));
        clientDetailsService.setClientDetailsStore(Collections.singletonMap(CLIENT_ID, clientDetails));

        // NO APPROVALS REQUIRED

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken);
        assertThat(accessToken, issuerUri(is(ISSUER_URI)));
        assertThat(accessToken, scope(is(requestedAuthScopes)));
        assertThat(accessToken, validFor(is(60 * 60 * 12)));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

        this.assertCommonEventProperties(accessToken, userId, buildJsonString(requestedAuthScopes));

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));

        assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken);
        assertThat(refreshedAccessToken, issuerUri(is(ISSUER_URI)));
        assertThat(refreshedAccessToken, scope(is(requestedAuthScopes)));
        assertThat(refreshedAccessToken, validFor(is(60 * 60 * 12)));
        assertThat(accessToken.getRefreshToken(), is(not(nullValue())));
    }

    @Test
    public void testCreateAccessTokenRefreshGrantSomeScopesAutoApprovedDowngradedRequest() throws InterruptedException {
        BaseClientDetails clientDetails = cloneClient(defaultClient);
        clientDetails.setAutoApproveScopes(singleton("true"));
        clientDetailsService.setClientDetailsStore(Collections.singletonMap(CLIENT_ID, clientDetails));

        // NO APPROVALS REQUIRED

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken);
        assertThat(accessToken, issuerUri(is(ISSUER_URI)));
        assertThat(accessToken, scope(is(requestedAuthScopes)));
        assertThat(accessToken, validFor(is(60 * 60 * 12)));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

        this.assertCommonEventProperties(accessToken, userId, buildJsonString(requestedAuthScopes));

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,readScope);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));

        assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken);
        assertThat(refreshedAccessToken, issuerUri(is(ISSUER_URI)));
        assertThat(refreshedAccessToken, validFor(is(60 * 60 * 12)));
        assertThat(accessToken.getRefreshToken(), is(not(nullValue())));
     }

    @Test
    public void testCreateAccessTokenRefreshGrantSomeScopesAutoApproved() throws InterruptedException {
        BaseClientDetails clientDetails = cloneClient(defaultClient);
        clientDetails.setAutoApproveScopes(readScope);
        clientDetailsService.setClientDetailsStore(Collections.singletonMap(CLIENT_ID, clientDetails));

        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        Calendar updatedAt = Calendar.getInstance();
        updatedAt.add(Calendar.MILLISECOND, -1000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(OPENID)
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken);
        assertThat(accessToken, issuerUri(is(ISSUER_URI)));
        assertThat(accessToken, scope(is(requestedAuthScopes)));
        assertThat(accessToken, validFor(is(60 * 60 * 12)));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

        this.assertCommonEventProperties(accessToken, userId, buildJsonString(requestedAuthScopes));

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));

        assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken);
        assertThat(refreshedAccessToken, issuerUri(is(ISSUER_URI)));
        assertThat(refreshedAccessToken, validFor(is(60 * 60 * 12)));
        assertThat(accessToken.getRefreshToken(), is(not(nullValue())));
    }

    @Test(expected = InvalidTokenException.class)
    public void testCreateAccessTokenRefreshGrantNoScopesAutoApprovedIncompleteApprovals() throws InterruptedException {
        BaseClientDetails clientDetails = cloneClient(defaultClient);
        clientDetails.setAutoApproveScopes(Arrays.asList());
        clientDetailsService.setClientDetailsStore(Collections.singletonMap(CLIENT_ID, clientDetails));

        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        Calendar updatedAt = Calendar.getInstance();
        updatedAt.add(Calendar.MILLISECOND, -1000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken);
        assertThat(accessToken, issuerUri(is(ISSUER_URI)));
        assertThat(accessToken, scope(is(requestedAuthScopes)));
        assertThat(accessToken, validFor(is(60 * 60 * 12)));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

        this.assertCommonEventProperties(accessToken, userId, buildJsonString(requestedAuthScopes));

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));
    }

    @Test
    public void testCreateAccessTokenRefreshGrantAllScopesAutoApprovedButApprovalDenied() throws InterruptedException {
        BaseClientDetails clientDetails = cloneClient(defaultClient);
        clientDetails.setAutoApproveScopes(requestedAuthScopes);
        clientDetailsService.setClientDetailsStore(Collections.singletonMap(CLIENT_ID, clientDetails));

        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        Calendar updatedAt = Calendar.getInstance();
        updatedAt.add(Calendar.MILLISECOND, -1000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.DENIED)
            .setLastUpdatedAt(updatedAt.getTime()));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken);
        assertThat(accessToken, issuerUri(is(ISSUER_URI)));
        assertThat(accessToken, scope(is(requestedAuthScopes)));
        assertThat(accessToken, validFor(is(60 * 60 * 12)));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

        this.assertCommonEventProperties(accessToken, userId, buildJsonString(requestedAuthScopes));

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
        assertNotNull(refreshedAccessToken);
    }

    @Test
    public void refreshTokenNotCreatedIfGrantTypeRestricted() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, requestedAuthScopes);
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), defaultUserAuthentication);
        tokenServices.setRestrictRefreshGrant(true);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        assertThat(accessToken.getRefreshToken(), is(nullValue()));
    }

    @Test
    public void testCreateAccessTokenImplicitGrant() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, IMPLICIT);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken);
        assertThat(accessToken, issuerUri(is(ISSUER_URI)));
        assertThat(accessToken, validFor(is(60 * 60 * 12)));
        assertThat(accessToken.getRefreshToken(), is(nullValue()));

        this.assertCommonEventProperties(accessToken, userId, buildJsonString(requestedAuthScopes));
    }

    @Test
    public void create_id_token_with_roles_scope() {
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID));
        assertTrue(idTokenJwt.getClaims().contains("\"amr\":[\"ext\",\"rba\",\"mfa\"]"));
    }

    @Test
    public void create_id_token_with_amr_claim() throws Exception {
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID, ROLES));
        assertTrue(idTokenJwt.getClaims().contains("\"amr\":[\"ext\",\"rba\",\"mfa\"]"));
    }

    @Test
    public void create_id_token_with_acr_claim() throws Exception {
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID, ROLES));
        assertTrue(idTokenJwt.getClaims().contains("\"" + ClaimConstants.ACR + "\":{\"values\":[\""));
    }

    @Test
    public void create_id_token_without_roles_scope() {
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID));
        assertFalse(idTokenJwt.getClaims().contains("\"roles\""));
    }

    @Test
    public void create_id_token_with_profile_scope() throws Exception {
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID, PROFILE));
        assertTrue(idTokenJwt.getClaims().contains("\"given_name\":\"" + defaultUser.getGivenName() + "\""));
        assertTrue(idTokenJwt.getClaims().contains("\"family_name\":\"" + defaultUser.getFamilyName() + "\""));
        assertTrue(idTokenJwt.getClaims().contains("\"phone_number\":\"" + defaultUser.getPhoneNumber() + "\""));
    }

    @Test
    public void create_id_token_without_profile_scope() throws Exception {
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID));
        assertFalse(idTokenJwt.getClaims().contains("\"given_name\":"));
        assertFalse(idTokenJwt.getClaims().contains("\"family_name\":"));
        assertFalse(idTokenJwt.getClaims().contains("\"phone_number\":"));
    }

    @Test
    public void create_id_token_with_last_logon_time_claim() {
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID));
        assertTrue(idTokenJwt.getClaims().contains("\"last_logon_time\":12345"));
    }

    private Jwt getIdToken(List<String> scopes) {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, scopes);

        authorizationRequest.setResponseTypes(new HashSet<>(Arrays.asList(CompositeAccessToken.ID_TOKEN)));

        UaaPrincipal uaaPrincipal = new UaaPrincipal(defaultUser.getId(), defaultUser.getUsername(), defaultUser.getEmail(), defaultUser.getOrigin(), defaultUser.getExternalId(), defaultUser.getZoneId());
        UaaAuthentication userAuthentication = new UaaAuthentication(uaaPrincipal, null, defaultUserAuthorities, new HashSet<>(Arrays.asList("group1", "group2")),Collections.EMPTY_MAP, null, true, System.currentTimeMillis(), System.currentTimeMillis() + 1000l * 60l);
        Set<String> amr = new HashSet<>();
        amr.addAll(Arrays.asList("ext", "mfa", "rba"));
        userAuthentication.setAuthenticationMethods(amr);
        userAuthentication.setAuthContextClassRef(new HashSet<>(Arrays.asList(AuthnContext.PASSWORD_AUTHN_CTX)));
        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        Jwt tokenJwt = JwtHelper.decode(accessToken.getValue());
        SignatureVerifier verifier = KeyInfo.getKey(tokenJwt.getHeader().getKid()).getVerifier();
        tokenJwt.verifySignature(verifier);
        assertNotNull(tokenJwt);

        Jwt idToken = JwtHelper.decode(((CompositeAccessToken) accessToken).getIdTokenValue());
        idToken.verifySignature(verifier);
        return idToken;
    }

    @Test
    public void testCreateAccessWithNonExistingScopes() {
        List<String> scopesThatDontExist = Arrays.asList("scope1","scope2");
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, scopesThatDontExist);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, IMPLICIT);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken);
        assertThat(accessToken, issuerUri(is(ISSUER_URI)));
        assertThat(accessToken, scope(is(scopesThatDontExist)));
        assertThat(accessToken, validFor(is(60 * 60 * 12)));
        assertThat(accessToken.getRefreshToken(), is(nullValue()));

        this.assertCommonEventProperties(accessToken, userId, buildJsonString(scopesThatDontExist));
    }

    @Test
    public void createAccessToken_forUser_inanotherzone() {
        String subdomain = "test-zone-subdomain";
        IdentityZone identityZone = getIdentityZone(subdomain);
        identityZone.setConfig(
            JsonUtils.readValue(
                "{\"tokenPolicy\":{\"accessTokenValidity\":3600,\"refreshTokenValidity\":9600}}",
                IdentityZoneConfiguration.class
            )
        );
        IdentityZoneHolder.set(identityZone);

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken);
        assertThat(accessToken, issuerUri(is("http://test-zone-subdomain.localhost:8080/uaa/oauth/token")));
        assertThat(accessToken, scope(is(requestedAuthScopes)));
        assertThat(accessToken, validFor(is(3600)));
        assertThat(accessToken.getRefreshToken(), is(not(nullValue())));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is("http://test-zone-subdomain.localhost:8080/uaa/oauth/token")));
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(9600)));

        this.assertCommonEventProperties(accessToken, userId, buildJsonString(requestedAuthScopes));
    }

    private String buildJsonString(List<String> list) {
        StringBuffer buf = new StringBuffer("[");
        int count = list.size();
        for (String s : list) {
            buf.append("\"");
            buf.append(s);
            buf.append("\"");
            if (--count > 0) {
                buf.append(",");
            }
        }
        buf.append("]");
        return buf.toString();
    }

    @Test
    public void testCreateAccessTokenAuthcodeGrantNarrowerScopes() {
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        Calendar updatedAt = Calendar.getInstance();
        updatedAt.add(Calendar.MILLISECOND, -1000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));

        // First Request
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        assertThat(accessToken, scope(is(requestedAuthScopes)));
        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        assertThat(refreshToken, is(not(nullValue())));

        assertThat(refreshToken, OAuth2RefreshTokenMatchers.scope(is(requestedAuthScopes)));
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.audience(is(resourceIds)));

        // Second request with reduced scopes
        AuthorizationRequest reducedScopeAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,readScope);
        reducedScopeAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(reducedScopeAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        reducedScopeAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2Authentication reducedScopeAuthentication = new OAuth2Authentication(reducedScopeAuthorizationRequest.createOAuth2Request(),userAuthentication);
        OAuth2AccessToken reducedScopeAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(reducedScopeAuthorizationRequest,"refresh_token"));

        // AT should have the new scopes, RT should be the same
        assertThat(reducedScopeAccessToken, scope(is(readScope)));
        assertEquals(reducedScopeAccessToken.getRefreshToken(), accessToken.getRefreshToken());
    }

    @Test(expected = InvalidScopeException.class)
    public void testCreateAccessTokenAuthcodeGrantExpandedScopes() {
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED));
        // First Request
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        assertThat(accessToken, scope(is(requestedAuthScopes)));
        assertThat(accessToken.getRefreshToken(), is(not(nullValue())));

        assertThat(accessToken.getRefreshToken(), OAuth2RefreshTokenMatchers.scope(is(requestedAuthScopes)));
        assertThat(accessToken.getRefreshToken(), OAuth2RefreshTokenMatchers.audience(is(resourceIds)));

        // Second request with expanded scopes
        AuthorizationRequest expandedScopeAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,expandedScopes);
        expandedScopeAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(expandedScopeAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        expandedScopeAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2Authentication expandedScopeAuthentication = new OAuth2Authentication(expandedScopeAuthorizationRequest.createOAuth2Request(),userAuthentication);
        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(expandedScopeAuthorizationRequest, "refresh_token"));
    }

    @Test
    public void testChangedExpiryForTokens() {
        BaseClientDetails clientDetails = cloneClient(defaultClient);
        clientDetails.setAccessTokenValiditySeconds(3600);
        clientDetails.setRefreshTokenValiditySeconds(36000);
        clientDetailsService.setClientDetailsStore(Collections.singletonMap(CLIENT_ID, clientDetails));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        assertThat(accessToken, validFor(is(3600)));
        assertThat(accessToken.getRefreshToken(), is(not(nullValue())));

        assertThat(accessToken.getRefreshToken(), OAuth2RefreshTokenMatchers.validFor(is(36000)));
    }

    @Test(expected = TokenRevokedException.class)
    public void testUserUpdatedAfterRefreshTokenIssued() {
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED));
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        UaaUser user = userDatabase.retrieveUserByName(username, OriginKeys.UAA);
        UaaUser newUser = new UaaUser(new UaaUserPrototype()
            .withId(userId)
            .withUsername(user.getUsername())
            .withPassword("blah")
            .withEmail(user.getEmail())
            .withAuthorities(user.getAuthorities()));
        userDatabase.updateUser(userId, newUser);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));
    }

    @Test(expected = InvalidTokenException.class)
    public void testRefreshTokenExpiry() {
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED));

        BaseClientDetails clientDetails = cloneClient(defaultClient);
        // Back date the refresh token. Crude way to do this but i'm not sure of
        // another
        clientDetails.setRefreshTokenValiditySeconds(-36000);
        clientDetailsService.setClientDetailsStore(Collections.singletonMap(CLIENT_ID, clientDetails));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
    }

    @Test(expected = InvalidTokenException.class)
    public void testRefreshTokenAfterApprovalsRevoked() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED));

        // Other scope is left unapproved

        for(Approval approval : approvalStore.getApprovals(userId, CLIENT_ID)) {
            approvalStore.revokeApproval(approval);
        }

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
    }

    @Test(expected = InvalidTokenException.class)
    public void testRefreshTokenAfterApprovalsExpired() {
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, -3000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
    }

    @Test(expected = InvalidTokenException.class)
    public void testRefreshTokenAfterApprovalsDenied() {
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, -3000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.DENIED));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
    }

    @Test(expected = InvalidTokenException.class)
    public void testRefreshTokenAfterApprovalsMissing() {
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, -3000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.DENIED));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
    }

    @Test(expected = InvalidTokenException.class)
    public void testRefreshTokenAfterApprovalsMissing2() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));
    }

    @Test
    public void refreshAccessTokenWithGrantTypeRestricted() {
        expectedEx.expect(InsufficientScopeException.class);
        expectedEx.expectMessage("Expected scope "+ UAA_REFRESH_TOKEN+" is missing");

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, requestedAuthScopes);
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), defaultUserAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest reducedScopeAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, readScope);
        reducedScopeAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(reducedScopeAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        reducedScopeAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.setRestrictRefreshGrant(true);
        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(reducedScopeAuthorizationRequest, "refresh_token"));
    }

    @Test
    public void refreshAccessTokenWithGrantTypeRestricted_butRefreshScopePresent() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, Arrays.asList(UAA_REFRESH_TOKEN));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), defaultUserAuthentication);
        tokenServices.setRestrictRefreshGrant(true);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest reducedScopeAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, null);
        reducedScopeAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(reducedScopeAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        reducedScopeAuthorizationRequest.setRequestParameters(refreshAzParameters);

        expiresAt.add(Calendar.MILLISECOND, 300000);
        updatedAt.add(Calendar.MILLISECOND, -1000);
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(UAA_REFRESH_TOKEN)
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));

        tokenServices.setRestrictRefreshGrant(true);
        OAuth2AccessToken refresh_token = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(reducedScopeAuthorizationRequest, "refresh_token"));
        assertNotNull(refresh_token);
    }

    @Test
    public void testReadAccessToken() {
        readAccessToken(EMPTY_SET);
    }

    @Test
    public void testReadAccessToken_No_PII() {
        readAccessToken(new HashSet<>(Arrays.asList(ClaimConstants.EMAIL, ClaimConstants.USER_NAME)));
    }

    public void readAccessToken(Set<String> excludedClaims) {
        tokenServices.setExcludedClaims(excludedClaims);
        AuthorizationRequest authorizationRequest =new AuthorizationRequest(CLIENT_ID, requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);
        Calendar updatedAt = Calendar.getInstance();
        updatedAt.add(Calendar.MILLISECOND, -1000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));
        Approval approval = new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(OPENID)
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime());
        approvalStore.addApproval(
            approval);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        assertEquals(accessToken, tokenServices.readAccessToken(accessToken.getValue()));

        approvalStore.revokeApproval(approval);
        try {
            tokenServices.readAccessToken(accessToken.getValue());
            fail("Approval has been revoked");
        } catch (InvalidTokenException x) {
            assertThat("Exception should be about approvals", x.getMessage().contains("some requested scopes are not approved"));
        }
    }

    @Test(expected = InvalidTokenException.class)
    public void testReadAccessTokenForDeletedUserId() {
        AuthorizationRequest authorizationRequest =new AuthorizationRequest(CLIENT_ID, requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);
        Calendar updatedAt = Calendar.getInstance();
        updatedAt.add(Calendar.MILLISECOND, -1000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.userDatabase.clear();
        assertEquals(accessToken, tokenServices.readAccessToken(accessToken.getValue()));
    }

    @Test
    public void testLoadAuthenticationForAUser() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        OAuth2Authentication loadedAuthentication = tokenServices.loadAuthentication(accessToken.getValue());

        assertEquals(USER_AUTHORITIES, loadedAuthentication.getAuthorities());
        assertEquals(username, loadedAuthentication.getName());
        UaaPrincipal uaaPrincipal = (UaaPrincipal)defaultUserAuthentication.getPrincipal();
        assertEquals(uaaPrincipal, loadedAuthentication.getPrincipal());
        assertNull(loadedAuthentication.getDetails());

        Authentication userAuth = loadedAuthentication.getUserAuthentication();
        assertEquals(username, userAuth.getName());
        assertEquals(uaaPrincipal, userAuth.getPrincipal());
        assertTrue(userAuth.isAuthenticated());
    }

    @Test
    public void testLoad_Opaque_AuthenticationForAUser() {
        defaultClient.setAutoApproveScopes(singleton("true"));
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResponseTypes(new HashSet(Arrays.asList(CompositeAccessToken.ID_TOKEN, "token")));
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        azParameters.put(REQUEST_TOKEN_FORMAT, TokenConstants.OPAQUE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        assertNotNull(accessToken);
        assertTrue("Token should be composite token", accessToken instanceof CompositeAccessToken);
        CompositeAccessToken composite = (CompositeAccessToken)accessToken;
        assertThat("id_token should be JWT, thus longer than 36 characters", composite.getIdTokenValue().length(), greaterThan(36));
        assertThat("Opaque access token must be shorter than 37 characters", accessToken.getValue().length(), lessThanOrEqualTo(36));
        assertThat("Opaque refresh token must be shorter than 37 characters", accessToken.getRefreshToken().getValue().length(), lessThanOrEqualTo(36));

        String accessTokenValue = tokenProvisioning.retrieve(composite.getValue()).getValue();
        Map<String,Object> accessTokenClaims = tokenServices.validateToken(accessTokenValue).getClaims();
        assertEquals(true, accessTokenClaims.get(ClaimConstants.REVOCABLE));

        String refreshTokenValue = tokenProvisioning.retrieve(composite.getRefreshToken().getValue()).getValue();
        Map<String,Object> refreshTokenClaims = tokenServices.validateToken(refreshTokenValue).getClaims();
        assertEquals(true, refreshTokenClaims.get(ClaimConstants.REVOCABLE));


        OAuth2Authentication loadedAuthentication = tokenServices.loadAuthentication(accessToken.getValue());

        assertEquals(USER_AUTHORITIES, loadedAuthentication.getAuthorities());
        assertEquals(username, loadedAuthentication.getName());
        UaaPrincipal uaaPrincipal = (UaaPrincipal)defaultUserAuthentication.getPrincipal();
        assertEquals(uaaPrincipal, loadedAuthentication.getPrincipal());
        assertNull(loadedAuthentication.getDetails());

        Authentication userAuth = loadedAuthentication.getUserAuthentication();
        assertEquals(username, userAuth.getName());
        assertEquals(uaaPrincipal, userAuth.getPrincipal());
        assertTrue(userAuth.isAuthenticated());

        Map<String,String> params = new HashedMap();
        params.put("grant_type", "refresh_token");
        params.put("client_id",CLIENT_ID);
        OAuth2AccessToken newAccessToken = tokenServices.refreshAccessToken(composite.getRefreshToken().getValue(), new TokenRequest(params, CLIENT_ID, Collections.EMPTY_SET, "refresh_token"));
        System.out.println("newAccessToken = " + newAccessToken);
    }


    @Test
    public void testLoadAuthenticationForAClient() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, CLIENT_CREDENTIALS);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        OAuth2Authentication loadedAuthentication = tokenServices.loadAuthentication(accessToken.getValue());

        assertThat("Client authorities match.",
                   loadedAuthentication.getAuthorities(),
                   containsInAnyOrder(AuthorityUtils.commaSeparatedStringToAuthorityList(CLIENT_AUTHORITIES).toArray())
        );
        assertEquals(CLIENT_ID, loadedAuthentication.getName());
        assertEquals(CLIENT_ID, loadedAuthentication.getPrincipal());
        assertNull(loadedAuthentication.getDetails());

        assertNull(loadedAuthentication.getUserAuthentication());
    }

    @Test(expected = InvalidTokenException.class)
    public void testLoadAuthenticationWithAnExpiredToken() throws InterruptedException {
        BaseClientDetails shortExpiryClient = defaultClient;
        shortExpiryClient.setAccessTokenValiditySeconds(1);
        clientDetailsService.setClientDetailsStore(Collections.singletonMap(CLIENT_ID, shortExpiryClient));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        assertThat(accessToken, validFor(is(1)));

        Thread.sleep(1000l);
        tokenServices.loadAuthentication(accessToken.getValue());
    }

    @Test
    public void testCreateAccessTokenAuthcodeGrantAdditionalAuthorizationAttributes() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        azParameters.put("authorities","{\"az_attr\":{\"external_group\":\"domain\\\\group1\", \"external_id\":\"abcd1234\"}}");
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken token = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(token);
        assertThat(token, issuerUri(is(ISSUER_URI)));
        assertThat(token, scope(is(requestedAuthScopes)));
        assertThat(token, validFor(is(60 * 60 * 12)));

        OAuth2RefreshToken refreshToken = token.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

        this.assertCommonEventProperties(token, userId, buildJsonString(requestedAuthScopes));

        Map<String, String> azMap = new LinkedHashMap<>();
        azMap.put("external_group", "domain\\group1");
        azMap.put("external_id", "abcd1234");
        assertEquals(azMap, token.getAdditionalInformation().get("az_attr"));
    }

    private BaseClientDetails cloneClient(ClientDetails client) {
        return new BaseClientDetails(client);
    }

    @SuppressWarnings("unchecked")
    private void assertCommonClientAccessTokenProperties(OAuth2AccessToken accessToken) {
        assertThat(accessToken, allOf(clientId(is(CLIENT_ID)),
                                      userId(is(nullValue())),
                                      subject(is(CLIENT_ID)),
                                      username(is(nullValue())),
                                      cid(is(CLIENT_ID)),
                                      scope(is(clientScopes)),
                                      audience(is(resourceIds)),
                                      jwtId(not(isEmptyString())),
                                      issuedAt(is(greaterThan(0))),
                                      expiry(is(greaterThan(0)))));
    }

    @SuppressWarnings({ "unused", "unchecked" })
    private void assertCommonUserAccessTokenProperties(OAuth2AccessToken accessToken) {
        assertThat(accessToken, allOf(username(is(username)),
                                      clientId(is(CLIENT_ID)),
                                      subject(is(userId)),
                                      audience(is(resourceIds)),
                                      origin(is(OriginKeys.UAA)),
                                      revocationSignature(is(not(nullValue()))),
                                      cid(is(CLIENT_ID)),
                                      userId(is(userId)),
                                      email(is(email)),
                                      jwtId(not(isEmptyString())),
                                      issuedAt(is(greaterThan(0))),
                                      expiry(is(greaterThan(0)))
                                    ));
    }

    @SuppressWarnings("unchecked")
    private void assertCommonUserRefreshTokenProperties(OAuth2RefreshToken refreshToken) {
        assertThat(refreshToken, allOf(/*issuer(is(issuerUri)),*/
                                        OAuth2RefreshTokenMatchers.username(is(username)),
                                        OAuth2RefreshTokenMatchers.clientId(is(CLIENT_ID)),
                                        OAuth2RefreshTokenMatchers.subject(is(not(nullValue()))),
                                        OAuth2RefreshTokenMatchers.audience(is(resourceIds)),
                                        OAuth2RefreshTokenMatchers.origin(is(OriginKeys.UAA)),
                                        OAuth2RefreshTokenMatchers.revocationSignature(is(not(nullValue()))),
                                        OAuth2RefreshTokenMatchers.jwtId(not(isEmptyString())),
                                        OAuth2RefreshTokenMatchers.issuedAt(is(greaterThan(0))),
                                        OAuth2RefreshTokenMatchers.expiry(is(greaterThan(0)))
                                      )
                  );
    }

    private void assertCommonEventProperties(OAuth2AccessToken accessToken, String expectedPrincipalId, String expectedData) {
        Assert.assertEquals(1, publisher.getEventCount());

        TokenIssuedEvent event = publisher.getLatestEvent();
        Assert.assertEquals(accessToken, event.getSource());
        Assert.assertEquals(mockAuthentication, event.getAuthentication());
        AuditEvent auditEvent = event.getAuditEvent();
        Assert.assertEquals(expectedPrincipalId, auditEvent.getPrincipalId());
        Assert.assertEquals(expectedData, auditEvent.getData());
        Assert.assertEquals(AuditEventType.TokenIssuedEvent, auditEvent.getType());
    }
}
