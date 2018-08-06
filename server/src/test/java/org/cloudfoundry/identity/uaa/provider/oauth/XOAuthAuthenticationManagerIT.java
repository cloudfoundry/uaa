/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.provider.oauth;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.authentication.AccountNotPreCreatedException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalGroupAuthorizationEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.InvitedUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.NewUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.cache.ExpiringUrlCache;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.TokenKeyEndpoint;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeToken;
import org.cloudfoundry.identity.uaa.oauth.token.VerificationKeyResponse;
import org.cloudfoundry.identity.uaa.oauth.token.VerificationKeysListResponse;
import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.RawXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.user.InMemoryUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.user.UserInfo;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.MalformedURLException;
import java.net.URL;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.entry;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.map;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withBadRequest;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

public class XOAuthAuthenticationManagerIT {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private MockRestServiceServer mockUaaServer;
    private XOAuthAuthenticationManager xoAuthAuthenticationManager;
    private ScimGroupExternalMembershipManager externalMembershipManager;
    private IdentityProviderProvisioning provisioning;
    private InMemoryUaaUserDatabase userDatabase;
    private XOAuthCodeToken xCodeToken;
    private ApplicationEventPublisher publisher;
    private static final String CODE = "the_code";

    private static final String ORIGIN = "the_origin";
    private static final String ISSUER = "cf-app.com";
    private static final String UAA_ISSUER_URL = "http://issuer.url";
    public static final List<String> SCOPES_LIST = Arrays.asList("openid", "some.other.scope", "closedid");

    private IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider;
    private Map<String, Object> claims;
    private HashMap<String, Object> attributeMappings;
    private OIDCIdentityProviderDefinition config;
    private RsaSigner signer;
    private Map<String, Object> header;
    private String invalidRsaSigningKey;
    private XOAuthProviderConfigurator xoAuthProviderConfigurator;
    private TokenEndpointBuilder tokenEndpointBuilder;

    private static final String PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" +
        "MFswDQYJKoZIhvcNAQEBBQADSgAwRwJAcjAgsHEfrUxeTFwQPb17AkZ2Im4SfZdp\n" +
        "Y8Ada9pZfxXz1PZSqv9TPTMAzNx+EkzMk2IMYN+uNm1bfDzaxVdz+QIDAQAB\n" +
        "-----END PUBLIC KEY-----";

    private static final String PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\n" +
        "MIIBOQIBAAJAcjAgsHEfrUxeTFwQPb17AkZ2Im4SfZdpY8Ada9pZfxXz1PZSqv9T\n" +
        "PTMAzNx+EkzMk2IMYN+uNm1bfDzaxVdz+QIDAQABAkBoR39y4rw0/QsY3PKQD5xo\n" +
        "hYSZCMCmJUI/sFCuECevIFY4h6q9KBP+4Set96f7Bgs9wJWVvCMx/nJ6guHAjsIB\n" +
        "AiEAywVOoCGIZ2YzARXWYcMRYZ89hxoHh8kZ+QMthRSZieECIQCP/GWQYgyofAQA\n" +
        "BtM8YwThXEV+S3KtuCn4IAQ89gqdGQIgULBASpZpPyc4OEM0nFBKFTGT46EtwwLj\n" +
        "RrvDmLPSPiECICQi9FqIQSUH+vkGvX0qXM8ymT5ZMS7oSaA8aNPj7EYBAiEAx5V3\n" +
        "2JGEulMY3bK1PVGYmtsXF1gq6zbRMoollMCRSMg=\n" +
        "-----END RSA PRIVATE KEY-----";
    private RestTemplate trustingRestTemplate;
    private RestTemplate nonTrustingRestTemplate;


    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }


    @Before
    public void setUp() throws Exception {
        RestTemplateConfig restTemplateConfig = new RestTemplateConfig();
        nonTrustingRestTemplate = restTemplateConfig.nonTrustingRestTemplate();
        trustingRestTemplate = restTemplateConfig.trustingRestTemplate();
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
        String keyName = "testKey";
        header = map(
            entry("alg", "HS256"),
            entry("kid", keyName),
            entry("typ", "JWT")
        );
        signer = new RsaSigner(PRIVATE_KEY);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap(keyName, PRIVATE_KEY));

        provisioning = mock(IdentityProviderProvisioning.class);
        externalMembershipManager = mock(ScimGroupExternalMembershipManager.class);

        for(String scope : SCOPES_LIST) {
            ScimGroupExternalMember member = new ScimGroupExternalMember();
            member.setDisplayName(scope);
            when(externalMembershipManager.getExternalGroupMapsByExternalGroup(eq(scope), anyString(), anyString()))
                    .thenReturn(Arrays.asList(member));
        }

        userDatabase = new InMemoryUaaUserDatabase(Collections.emptySet());
        publisher = mock(ApplicationEventPublisher.class);
        tokenEndpointBuilder = mock(TokenEndpointBuilder.class);
        when(tokenEndpointBuilder.getTokenEndpoint()).thenReturn(UAA_ISSUER_URL);
        xoAuthProviderConfigurator = spy(
            new XOAuthProviderConfigurator(
                provisioning,
                new ExpiringUrlCache(10000, new TimeServiceImpl(), 10),
              trustingRestTemplate,
              nonTrustingRestTemplate
            )
        );
        xoAuthAuthenticationManager = spy(new XOAuthAuthenticationManager(xoAuthProviderConfigurator, trustingRestTemplate, nonTrustingRestTemplate));
        xoAuthAuthenticationManager.setUserDatabase(userDatabase);
        xoAuthAuthenticationManager.setExternalMembershipManager(externalMembershipManager);
        xoAuthAuthenticationManager.setApplicationEventPublisher(publisher);
        xoAuthAuthenticationManager.setTokenEndpointBuilder(tokenEndpointBuilder);
        xCodeToken = new XOAuthCodeToken(CODE, ORIGIN, "http://localhost/callback/the_origin");
        claims = map(
            entry("sub", "12345"),
            entry("preferred_username", "marissa"),
            entry("origin", "uaa"),
            entry("iss", "http://oidc10.oms.identity.team/oauth/token"),
            entry("given_name", "Marissa"),
            entry("client_id", "client"),
            entry("aud", Arrays.asList("identity", "another_trusted_client")),
            entry("zid", "uaa"),
            entry("user_id", "12345"),
            entry("azp", "client"),
            entry("scope", Arrays.asList("openid")),
            entry("auth_time", 1458603913),
            entry("phone_number", "1234567890"),
            entry("exp", Instant.now().getEpochSecond() + 3600),
            entry("iat", 1458603913),
            entry("family_name", "Bloggs"),
            entry("jti", "b23fe183-158d-4adc-8aff-65c440bbbee1"),
            entry("email", "marissa@bloggs.com"),
            entry("rev_sig", "3314dc98"),
            entry("cid", "client"),
            entry("email_verified", true),
            entry(ClaimConstants.ACR, JsonUtils.readValue("{\"values\": [\"urn:oasis:names:tc:SAML:2.0:ac:classes:Password\"] }", Map.class))
        );

        attributeMappings = new HashMap<>();

        config = new OIDCIdentityProviderDefinition()
            .setAuthUrl(new URL("http://oidc10.oms.identity.team/oauth/authorize"))
            .setTokenUrl(new URL("http://oidc10.oms.identity.team/oauth/token"))
            .setIssuer("http://oidc10.oms.identity.team/oauth/token")
            .setShowLinkText(true)
            .setLinkText("My OIDC Provider")
            .setRelyingPartyId("identity")
            .setRelyingPartySecret("identitysecret")
            .setUserInfoUrl(new URL("http://oidc10.oms.identity.team/userinfo"))
            .setTokenKey(PUBLIC_KEY);
        config.setExternalGroupsWhitelist(
            Arrays.asList(
                "*"
            )
        );

        mockUaaServer = MockRestServiceServer.createServer(nonTrustingRestTemplate);
        reset(xoAuthAuthenticationManager);

        invalidRsaSigningKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIBOgIBAAJBAJnlBG4lLmUiHslsKDODfd0MqmGZRNUOhn7eO3cKobsFljUKzRQe\n" +
            "GB7LYMjPavnKccm6+jWSXutpzfAc9A9wXG8CAwEAAQJADwwdiseH6cuURw2UQLUy\n" +
            "sVJztmdOG6b375+7IMChX6/cgoF0roCPP0Xr70y1J4TXvFhjcwTgm4RI+AUiIDKw\n" +
            "gQIhAPQHwHzdYG1639Qz/TCHzuai0ItwVC1wlqKpat+CaqdZAiEAoXFyS7249mRu\n" +
            "xtwRAvxKMe+eshHvG2le+ZDrM/pz8QcCIQCzmCDpxGL7L7sbCUgFN23l/11Lwdex\n" +
            "uXKjM9wbsnebwQIgeZIbVovUp74zaQ44xT3EhVwC7ebxXnv3qAkIBMk526sCIDVg\n" +
            "z1jr3KEcaq9zjNJd9sKBkqpkVSqj8Mv+Amq+YjBA\n" +
            "-----END RSA PRIVATE KEY-----";
    }

    private static class OriginResultCaptor<T> implements Answer {

        Map<T, AtomicLong> counter = new HashMap<>();

        public OriginResultCaptor(List<T> origins) {
            for (T origin : origins) {
                counter.put(origin, new AtomicLong(0));
            }
        }

        @Override
        public T answer(InvocationOnMock invocation) throws Throwable {
            T origin = (T) invocation.callRealMethod();
            counter.get(origin).incrementAndGet();
            return origin;
        }

        public Map<T, AtomicLong> getCounter() {
            return counter;
        }
    }

    private static class TestRunner extends Thread {
        private final int loops;
        private final String origin;
        private final XOAuthAuthenticationManager manager;

        public TestRunner(int loops, String origin, XOAuthAuthenticationManager manager) {
            this.loops = loops;
            this.origin = origin;
            this.manager = manager;
        }

        public void run() {
            XOAuthCodeToken token = new XOAuthCodeToken("code", origin, null);
            for (int i=0; i<loops; i++) {
                manager.getExternalAuthenticationDetails(token);
            }
        }
    }

    @Test
    public void get_response_type_for_oauth2() {
        RawXOAuthIdentityProviderDefinition signed = new RawXOAuthIdentityProviderDefinition();
        signed.setResponseType("signed_request");
        RawXOAuthIdentityProviderDefinition token = new RawXOAuthIdentityProviderDefinition();
        OIDCIdentityProviderDefinition oidcIdentityProviderDefinition = new OIDCIdentityProviderDefinition();

        assertEquals("signed_request", xoAuthAuthenticationManager.getResponseType(signed));
        assertEquals("token", xoAuthAuthenticationManager.getResponseType(token));
        assertEquals("id_token", xoAuthAuthenticationManager.getResponseType(oidcIdentityProviderDefinition));
    }

    @Test
    public void unknown_config_class() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Unknown type for provider.");

        xoAuthAuthenticationManager.getResponseType(new AbstractXOAuthIdentityProviderDefinition() {
            @Override
            public URL getAuthUrl() {
                return super.getAuthUrl();
            }
        });
    }

    @Test
    public void verify_hmac_256_signature() throws Exception {
        String key = "key";
        String data = "data";
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);
        byte[] hmacData = mac.doFinal(data.getBytes("UTF-8"));
        assertThat(new String(Base64.encodeBase64URLSafe(hmacData)), equalTo(xoAuthAuthenticationManager.hmacSignAndEncode(data, key)));
    }

    @Test
    public void race_condition_in_get_auth_details() throws Exception {
        /*
         * This tests demonstrates the race condition in setOrigin/getOrigin
         * in the authentication manager.
         */
        List<String> origins = Arrays.asList(ORIGIN, "origin-2", "origin-3", "origin-4");
        OriginResultCaptor<String> getOriginCaptor = new OriginResultCaptor(origins);
        doAnswer(getOriginCaptor).when(xoAuthAuthenticationManager).getOrigin();
        int loops = 10000;
        List<Thread> threads = new LinkedList<>();

        //run one thread for each origin
        for (String origin : origins) {
            threads.add(new TestRunner(loops, origin, xoAuthAuthenticationManager));
        }
        for (Thread t : threads) {
            t.start();
        }
        for (Thread t : threads) {
            t.join();
        }
        //all threads completed

        ArgumentCaptor<String> setOriginCaptor = ArgumentCaptor.forClass(String.class);
        verify(xoAuthAuthenticationManager, times(loops*origins.size())).setOrigin(setOriginCaptor.capture());

        //we have called setOrigin exactly once per iteration
        assertEquals(loops*origins.size(), setOriginCaptor.getAllValues().size());
        //getOrigin has returned the correct value exact times
        for (String origin : origins) {
            assertEquals(loops * 2, getOriginCaptor.getCounter().get(origin).get());
        }
    }

    @Test
    public void when_origin_provided_no_call_resolve_based_on_issuer() {
        xoAuthAuthenticationManager.getUser(xCodeToken, getAuthenticationData(xCodeToken));
        verify(xoAuthAuthenticationManager, never()).resolveOriginProvider(anyString(), anyString());
    }

    @Test
    public void resolve_provider_by_issuer_null_id_token() throws Exception {
        xCodeToken = new XOAuthCodeToken(null,null,null,null,null,null);
        exception.expect(InsufficientAuthenticationException.class);
        exception.expectMessage("Unable to decode expected id_token");
        getAuthenticationData(xCodeToken);
    }

    @Test
    public void unable_to_resolve_to_single_provider() throws Exception {
        String issuer = "http://oidc10.oms.identity.team/oauth/token";
        CompositeToken token = getCompositeAccessToken();
        xCodeToken = new XOAuthCodeToken(null,null,null,token.getIdTokenValue(),null,null);
        exception.expect(InsufficientAuthenticationException.class);
        exception.expectMessage(String.format("Unable to map issuer, %s , to a single registered provider", issuer));
        String zoneId = IdentityZoneHolder.get().getId();
        when(provisioning.retrieveAll(eq(true), eq(zoneId))).thenReturn(emptyList());
        getAuthenticationData(xCodeToken);
    }

    @Test
    public void issuer_missing_in_id_token() throws Exception {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> provider = getProvider();
        exception.expect(InsufficientAuthenticationException.class);
        exception.expectMessage("Issuer is missing in id_token");
        CompositeToken token = getCompositeAccessToken(Arrays.asList(ClaimConstants.ISS));
        xCodeToken = new XOAuthCodeToken(null,null,null,token.getIdTokenValue(),null,null);
        //perform test
        getAuthenticationData(xCodeToken);
    }

    @Test
    public void origin_is_resolved_based_on_issuer_and_id_token() throws Exception {
        CompositeToken token = getCompositeAccessToken();
        xCodeToken = new XOAuthCodeToken(null,null,null,token.getIdTokenValue(),null,null);
        when(provisioning.retrieveAll(eq(true), anyString())).thenReturn(Arrays.asList(getProvider()));
        //perform test
        getAuthenticationData(xCodeToken);

        ArgumentCaptor<String> idTokenCaptor = ArgumentCaptor.forClass(String.class);
        verify(xoAuthAuthenticationManager, times(1)).resolveOriginProvider(idTokenCaptor.capture(), any());
        verify(provisioning, never()).retrieveByOrigin(anyString(), anyString());
        verify(xoAuthProviderConfigurator, times(1)).retrieveByIssuer(eq("http://oidc10.oms.identity.team/oauth/token"), anyString());
        assertEquals(token.getIdTokenValue(), idTokenCaptor.getValue());
    }

    @Test
    public void origin_is_resolved_when_using_internal_idp() throws Exception {
        String issuerURL = "http://issuer.url";
        String contextPathURL = "http://contextPath.url";
        when(tokenEndpointBuilder.getTokenEndpoint()).thenReturn(issuerURL);
        claims.put("iss", issuerURL);
        CompositeToken token = getCompositeAccessToken();
        IdentityProvider idp = xoAuthAuthenticationManager.resolveOriginProvider(token.getIdTokenValue(), contextPathURL);

        assertNotNull(idp);
        assertTrue(idp.getConfig() instanceof AbstractXOAuthIdentityProviderDefinition);

        AbstractXOAuthIdentityProviderDefinition idpConfig = (AbstractXOAuthIdentityProviderDefinition) idp.getConfig();

        assertEquals(contextPathURL + "/token_keys", idpConfig.getTokenKeyUrl().toString());
    }

    @Test
    public void if_internal_idp_use_local_keys() throws Exception {
        String contextPathURL = "http://contextPath.url";
        claims.put("iss", UAA_ISSUER_URL);
        CompositeToken token = getCompositeAccessToken();
        String idToken = token.getIdTokenValue();
        xCodeToken.setIdToken(idToken);
        xCodeToken.setOrigin(null);
        xCodeToken.setRequestContextPath(contextPathURL);


        xoAuthAuthenticationManager
            .getExternalAuthenticationDetails(xCodeToken);

        verify(xoAuthAuthenticationManager, times(1)).getClaimsFromToken(same(xCodeToken), any());
        verify(xoAuthAuthenticationManager, times(1)).getClaimsFromToken(eq(idToken), any());
        verify(xoAuthAuthenticationManager, times(1)).getTokenKeyForUaaOrigin();
    }

    @Test
    public void discoveryURL_is_used() throws MalformedURLException {
        URL authUrl = config.getAuthUrl();
        URL tokenUrl = config.getTokenUrl();

        config.setAuthUrl(null);
        config.setTokenUrl(null);
        config.setDiscoveryUrl(new URL("http://some.discovery.url"));

        Map<String, Object> discoveryContent = new HashMap();
        discoveryContent.put("authorization_endpoint", authUrl.toString());
        discoveryContent.put("token_endpoint", tokenUrl.toString());
        //mandatory but not used
        discoveryContent.put("userinfo_endpoint", "http://localhost/userinfo");
        discoveryContent.put("jwks_uri", "http://localhost/token_keys");
        discoveryContent.put("issuer", "http://localhost/issuer");

        mockUaaServer.expect(requestTo("http://some.discovery.url"))
            .andRespond(withStatus(OK).contentType(APPLICATION_JSON).body(JsonUtils.writeValueAsBytes(discoveryContent)));

        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = getProvider();
        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        mockToken();
        addTheUserOnAuth();
        xoAuthAuthenticationManager.authenticate(xCodeToken);
        verify(xoAuthProviderConfigurator, atLeast(1)).overlay(eq(config));
        mockUaaServer.verify();

    }

    @Test
    public void clientAuthInBody_is_used() throws MalformedURLException {
        config.setClientAuthInBody(true);
        mockUaaServer.expect(requestTo(config.getTokenUrl().toString()))
                .andExpect(request -> assertThat("Check Auth header not present", request.getHeaders().get("Authorization"), nullValue()))
                .andExpect(content().string(containsString("client_id="+config.getRelyingPartyId())))
                .andExpect(content().string(containsString("client_secret="+config.getRelyingPartySecret())))
                .andRespond(withStatus(OK).contentType(APPLICATION_JSON).body(getIdTokenResponse()));
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = getProvider();
        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        xoAuthAuthenticationManager.getClaimsFromToken(xCodeToken, config);

        mockUaaServer.verify();
    }


    @Test
    public void idToken_In_Redirect_Should_Use_it() throws Exception {
        mockToken();
        addTheUserOnAuth();
        String tokenResponse = getIdTokenResponse();
        String idToken = (String) JsonUtils.readValue(tokenResponse, Map.class).get("id_token");
        xCodeToken.setIdToken(idToken);
        xoAuthAuthenticationManager.authenticate(xCodeToken);

        verify(xoAuthAuthenticationManager, times(1)).getClaimsFromToken(same(xCodeToken), any());
        verify(xoAuthAuthenticationManager, times(1)).getClaimsFromToken(eq(idToken), any());
        verify(xoAuthAuthenticationManager, never()).getRestTemplate(any());

        ArgumentCaptor<ApplicationEvent> userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(publisher,times(3)).publishEvent(userArgumentCaptor.capture());
        assertEquals(3, userArgumentCaptor.getAllValues().size());
        NewUserAuthenticatedEvent event = (NewUserAuthenticatedEvent)userArgumentCaptor.getAllValues().get(0);

        assertUserCreated(event);
    }

    @Test
    public void exchangeExternalCodeForIdToken_andCreateShadowUser() throws Exception {
        mockToken();
        addTheUserOnAuth();

        xoAuthAuthenticationManager.authenticate(xCodeToken);

        mockUaaServer.verify();

        ArgumentCaptor<ApplicationEvent> userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(publisher,times(3)).publishEvent(userArgumentCaptor.capture());
        assertEquals(3, userArgumentCaptor.getAllValues().size());
        NewUserAuthenticatedEvent event = (NewUserAuthenticatedEvent)userArgumentCaptor.getAllValues().get(0);

        assertUserCreated(event);
    }

    @Test
    public void test_single_key_response() throws Exception {
        configureTokenKeyResponse(
            "http://oidc10.oms.identity.team/token_key",
            PRIVATE_KEY,
            "correctKey",
            false);
        addTheUserOnAuth();
        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test
    public void test_single_key_response_without_value() throws Exception {
        String json = getKeyJson(PRIVATE_KEY, "correctKey", false);
        Map<String, Object> map = JsonUtils.readValue(json, new TypeReference<Map<String, Object>>() {});
        map.remove("value");
        json = JsonUtils.writeValueAsString(map);
        configureTokenKeyResponse("http://oidc10.oms.identity.team/token_key",json);
        addTheUserOnAuth();
        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test
    public void test_multi_key_response_without_value() throws Exception {
        String jsonValid = getKeyJson(PRIVATE_KEY, "correctKey", false);
        String jsonInvalid = getKeyJson(invalidRsaSigningKey, "invalidKey", false);
        Map<String, Object> mapValid = JsonUtils.readValue(jsonValid, new TypeReference<Map<String, Object>>() {});
        Map<String, Object> mapInvalid = JsonUtils.readValue(jsonInvalid, new TypeReference<Map<String, Object>>() {});
        mapValid.remove("value");
        mapInvalid.remove("value");
        String json = JsonUtils.writeValueAsString(new JsonWebKeySet<>(Arrays.asList(new JsonWebKey(mapInvalid), new JsonWebKey(mapValid))));
        configureTokenKeyResponse("http://oidc10.oms.identity.team/token_key",json);
        addTheUserOnAuth();
        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test
    public void test_multi_key_all_invalid() throws Exception {
        String jsonInvalid = getKeyJson(invalidRsaSigningKey, "invalidKey", false);
        String jsonInvalid2 = getKeyJson(invalidRsaSigningKey, "invalidKey2", false);
        Map<String, Object> mapInvalid = JsonUtils.readValue(jsonInvalid, new TypeReference<Map<String, Object>>() {});
        Map<String, Object> mapInvalid2 = JsonUtils.readValue(jsonInvalid2, new TypeReference<Map<String, Object>>() {});
        String json = JsonUtils.writeValueAsString(new JsonWebKeySet<>(Arrays.asList(new JsonWebKey(mapInvalid), new JsonWebKey(mapInvalid2))));
        assertTrue(json.contains("\"invalidKey\""));
        assertTrue(json.contains("\"invalidKey2\""));
        configureTokenKeyResponse("http://oidc10.oms.identity.team/token_key",json);
        addTheUserOnAuth();
        try {
            xoAuthAuthenticationManager.authenticate(xCodeToken);
            fail("not expected");
        } catch (Exception e) {
            assertTrue(e.getCause() instanceof InvalidSignatureException);
        }
    }


    @Test
    public void test_multi_key_response() throws Exception {
        configureTokenKeyResponse(
            "http://oidc10.oms.identity.team/token_key",
            PRIVATE_KEY,
            "correctKey",
            true);
        addTheUserOnAuth();
        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    public void assertUserCreated(NewUserAuthenticatedEvent event) {
        assertNotNull(event);
        UaaUser uaaUser = event.getUser();
        assertNotNull(uaaUser);
        assertEquals("Marissa",uaaUser.getGivenName());
        assertEquals("Bloggs", uaaUser.getFamilyName());
        assertEquals("marissa@bloggs.com", uaaUser.getEmail());
        assertEquals("the_origin", uaaUser.getOrigin());
        assertEquals("1234567890", uaaUser.getPhoneNumber());
        assertEquals("12345",uaaUser.getUsername());
        assertEquals(OriginKeys.UAA, uaaUser.getZoneId());
    }


    @Test(expected = AccountNotPreCreatedException.class)
    public void doesNotCreateShadowUserAndFailsAuthentication_IfAddShadowUserOnLoginIsFalse() throws Exception {
        config.setAddShadowUserOnLogin(false);
        mockToken();
        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test(expected = InvalidTokenException.class)
    public void rejectTokenWithInvalidSignature() throws Exception {
        mockToken();

        config.setTokenKey("WRONG_KEY");

        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test(expected = InvalidTokenException.class)
    public void rejectTokenWithInvalidSignatureAccordingToTokenKeyEndpoint() throws Exception {
        configureTokenKeyResponse("http://oidc10.oms.identity.team/token_key", invalidRsaSigningKey, "wrongKey");
        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    public void configureTokenKeyResponse(String keyUrl, String signingKey, String keyId) throws MalformedURLException {
        configureTokenKeyResponse(keyUrl, signingKey, keyId, false);
    }
    public void configureTokenKeyResponse(String keyUrl, String signingKey, String keyId, boolean list) throws MalformedURLException {
        String response = getKeyJson(signingKey, keyId, list);
        configureTokenKeyResponse(keyUrl, response);
    }

    public String getKeyJson(String signingKey, String keyId, boolean list) {
        KeyInfo key = new KeyInfo();
        key.setKeyId(keyId);
        key.setSigningKey(signingKey);
        VerificationKeyResponse keyResponse = TokenKeyEndpoint.getVerificationKeyResponse(key);
        Object verificationKeyResponse = list ? new VerificationKeysListResponse(Arrays.asList(keyResponse)) : keyResponse;
        return JsonUtils.writeValueAsString(verificationKeyResponse);
    }

    public void configureTokenKeyResponse(String keyUrl, String response) throws MalformedURLException {
        config.setTokenKey(null);
        config.setTokenKeyUrl(new URL(keyUrl));
        mockToken();
        mockUaaServer.expect(requestTo(keyUrl))
                .andExpect(header("Authorization", "Basic " + new String(Base64.encodeBase64("identity:identitysecret".getBytes()))))
                .andExpect(header("Accept", "application/json"))
                .andRespond(withStatus(OK).contentType(APPLICATION_JSON).body(response));
    }

    @Test(expected = InvalidTokenException.class)
    public void rejectTokenWithInvalidIssuer() throws Exception {
        claims.put("iss", "http://wrong.issuer/");
        mockToken();

        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test(expected = InvalidTokenException.class)
    public void rejectExpiredToken() throws Exception {
        claims.put("exp", Instant.now().getEpochSecond() - 1);
        mockToken();

        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test(expected = InvalidTokenException.class)
    public void rejectWrongAudience() throws Exception {
        claims.put("aud", Arrays.asList("another_client", "a_complete_stranger"));
        mockToken();

        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test
    public void updateShadowUser_IfAlreadyExists() throws MalformedURLException {
        claims.put("scope", SCOPES_LIST);
        attributeMappings.put(GROUP_ATTRIBUTE_NAME, "scope");
        mockToken();

        UaaUser existingShadowUser = new UaaUser(new UaaUserPrototype()
            .withUsername("12345")
            .withPassword("")
            .withEmail("marissa_old@bloggs.com")
            .withGivenName("Marissa_Old")
            .withFamilyName("Bloggs_Old")
            .withId("user-id")
            .withOrigin("the_origin")
            .withZoneId("uaa")
            .withAuthorities(UaaAuthority.USER_AUTHORITIES));

        userDatabase.addUser(existingShadowUser);

        xoAuthAuthenticationManager.authenticate(xCodeToken);
        mockUaaServer.verify();

        ArgumentCaptor<ApplicationEvent> userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(publisher,times(2)).publishEvent(userArgumentCaptor.capture());
        assertEquals(2, userArgumentCaptor.getAllValues().size());
        ExternalGroupAuthorizationEvent event = (ExternalGroupAuthorizationEvent)userArgumentCaptor.getAllValues().get(0);

        UaaUser uaaUser = event.getUser();
        assertEquals("Marissa",uaaUser.getGivenName());
        assertEquals("Bloggs",uaaUser.getFamilyName());
        assertEquals("marissa@bloggs.com", uaaUser.getEmail());
        assertEquals("the_origin", uaaUser.getOrigin());
        assertEquals("1234567890", uaaUser.getPhoneNumber());
        assertEquals("12345", uaaUser.getUsername());
        assertEquals(OriginKeys.UAA, uaaUser.getZoneId());
    }

    @Test
    public void invitedUser_becomesVerifiedOnAccept() throws Exception {
        getInvitedUser();

        claims.remove("preferred_username");
        claims.put("preferred_username", "marissa@bloggs.com");
        mockToken();

        xoAuthAuthenticationManager.authenticate(xCodeToken);
        mockUaaServer.verify();

        ArgumentCaptor<ApplicationEvent> userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(publisher,times(3)).publishEvent(userArgumentCaptor.capture());
        assertEquals(3, userArgumentCaptor.getAllValues().size());
        assertThat(userArgumentCaptor.getAllValues().get(0), instanceOf(InvitedUserAuthenticatedEvent.class));

        RequestContextHolder.resetRequestAttributes();
    }

    private UaaUser getInvitedUser() {
        UaaUser existingShadowUser = new UaaUser(new UaaUserPrototype()
            .withUsername("marissa@bloggs.com")
            .withPassword("")
            .withEmail("marissa@bloggs.com")
            .withGivenName("Marissa_Old")
            .withFamilyName("Bloggs_Old")
            .withId("user-id")
            .withOrigin("the_origin")
            .withZoneId("uaa")
            .withAuthorities(UaaAuthority.USER_AUTHORITIES));

        userDatabase.addUser(existingShadowUser);

        RequestAttributes attributes = new ServletRequestAttributes(new MockHttpServletRequest());
        attributes.setAttribute("IS_INVITE_ACCEPTANCE", true, RequestAttributes.SCOPE_SESSION);
        attributes.setAttribute("user_id", existingShadowUser.getId(), RequestAttributes.SCOPE_SESSION);
        RequestContextHolder.setRequestAttributes(attributes);

        return existingShadowUser;
    }

    @Test
    public void loginAndValidateSignatureUsingTokenKeyEndpoint() throws Exception {
        config.setTokenKeyUrl(new URL("http://oidc10.oms.identity.team/token_key"));
        config.setTokenKey(null);

        KeyInfo key = new KeyInfo();
        key.setKeyId("correctKey");
        key.setSigningKey(PRIVATE_KEY);
        VerificationKeyResponse verificationKeyResponse = TokenKeyEndpoint.getVerificationKeyResponse(key);
        String response = JsonUtils.writeValueAsString(verificationKeyResponse);

        mockToken();
        mockUaaServer.expect(requestTo("http://oidc10.oms.identity.team/token_key"))
                .andExpect(header("Authorization", "Basic " + new String(Base64.encodeBase64("identity:identitysecret".getBytes()))))
                .andExpect(header("Accept", "application/json"))
                .andRespond(withStatus(OK).contentType(APPLICATION_JSON).body(response));

        mockToken();

        UaaUser existingShadowUser = new UaaUser(new UaaUserPrototype()
                .withUsername("12345")
                .withPassword("")
                .withEmail("marissa_old@bloggs.com")
                .withGivenName("Marissa_Old")
                .withFamilyName("Bloggs_Old")
                .withId("user-id")
                .withOrigin("the_origin")
                .withZoneId("uaa")
                .withAuthorities(UaaAuthority.USER_AUTHORITIES));

        userDatabase.addUser(existingShadowUser);

        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test
    public void authenticatedUser_hasAuthoritiesFromListOfIDTokenRoles() throws MalformedURLException {
        claims.put("scope", SCOPES_LIST);
        config.setExternalGroupsWhitelist(Collections.emptyList());
        testTokenHasAuthoritiesFromIdTokenRoles();
    }

    @Test
    public void authenticatedUser_hasAuthoritiesFromCommaSeparatedStringOfIDTokenRoles() throws MalformedURLException {
        claims.put("scope", "openid,some.other.scope,closedid");
        testTokenHasAuthoritiesFromIdTokenRoles();
    }

    @Test
    public void authenticatedUser_hasConfigurableUsernameField() throws Exception {
        attributeMappings.put(USER_NAME_ATTRIBUTE_NAME, "username");

        claims.remove("preferred_username");
        claims.put("username", "marissa");
        mockToken();

        UaaUser uaaUser = xoAuthAuthenticationManager.getUser(xCodeToken, getAuthenticationData(xCodeToken));

        assertThat(uaaUser.getUsername(), is("marissa"));
    }

    @Test
    public void username_defaults_to_subject() throws Exception {
        claims.remove("preferred_username");
        mockToken();
        UaaUser uaaUser = xoAuthAuthenticationManager.getUser(xCodeToken, getAuthenticationData(xCodeToken));
        assertThat(uaaUser.getUsername(), is("12345"));
    }

    @Test
    public void missing_user_name_throws_auth_exception() throws Exception {
        exception.expect(InsufficientAuthenticationException.class);
        exception.expectMessage("Unable to map claim to a username");
        claims.remove("preferred_username");
        claims.remove("sub");
        mockToken();
        getAuthenticationData(xCodeToken);
    }

    @Test
    public void getUserWithNullEmail() throws MalformedURLException {
        claims.put("email", null);
        mockToken();
        UaaUser user = xoAuthAuthenticationManager.getUser(xCodeToken, getAuthenticationData(xCodeToken));

        assertEquals("12345@user.from.the_origin.cf", user.getEmail());
    }

    private XOAuthAuthenticationManager.AuthenticationData getAuthenticationData(XOAuthCodeToken xCodeToken) {
        return xoAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken);
    }

    @Test
    public void testGetUserSetsTheRightOrigin() {
        xoAuthAuthenticationManager.getUser(xCodeToken, getAuthenticationData(xCodeToken));
        assertEquals(ORIGIN, xoAuthAuthenticationManager.getOrigin());

        XOAuthCodeToken otherToken = new XOAuthCodeToken(CODE, "other_origin", "http://localhost/callback/the_origin");
        xoAuthAuthenticationManager.getUser(otherToken, getAuthenticationData(otherToken));
        assertEquals("other_origin", xoAuthAuthenticationManager.getOrigin());
    }

    @Test
    public void testGetUserIssuerOverrideNotUsed() throws Exception {
        mockToken();
        assertNotNull(xoAuthAuthenticationManager.getUser(xCodeToken, getAuthenticationData(xCodeToken)));
    }

    @Test
    public void testGetUserIssuerOverrideUsedNoMatch() throws Exception {
        config.setIssuer(ISSUER);
        mockToken();
        try {
            xoAuthAuthenticationManager.getUser(xCodeToken, getAuthenticationData(xCodeToken));
            fail("InvalidTokenException should have been thrown");
        } catch(InvalidTokenException ex) { }
    }

    @Test
    public void testGetUserIssuerOverrideUsedMatch() throws Exception {
        config.setIssuer(ISSUER);
        claims.remove("iss");
        claims.put("iss", ISSUER);
        mockToken();
        assertNotNull(xoAuthAuthenticationManager.getUser(xCodeToken, getAuthenticationData(xCodeToken)));
    }

    @Test
    public void test_authentication_context_transfers_to_authentication() throws Exception {
        addTheUserOnAuth();
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication)xoAuthAuthenticationManager.authenticate(xCodeToken);
        assertNotNull(authentication);
        assertNotNull(authentication.getAuthContextClassRef());
        assertThat(authentication.getAuthContextClassRef(), containsInAnyOrder("urn:oasis:names:tc:SAML:2.0:ac:classes:Password"));
    }

    @Test
    public void test_authentication_context_when_missing() throws Exception {
        addTheUserOnAuth();
        claims.remove(ClaimConstants.ACR);
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication)xoAuthAuthenticationManager.authenticate(xCodeToken);
        assertNotNull(authentication);
        assertNull(authentication.getAuthContextClassRef());
    }

    @Test
    public void failsIfProviderIsNotOIDCOrOAuth() throws Exception {
        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(MultitenancyFixture.identityProvider("the_origin", "uaa"));
        Authentication authentication = xoAuthAuthenticationManager.authenticate(xCodeToken);
        assertNull(authentication);
    }

    @Test
    public void failsIfProviderIsNotFound() throws Exception {
        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(null);
        Authentication authentication = xoAuthAuthenticationManager.authenticate(xCodeToken);
        assertNull(authentication);
    }

    @Test(expected = HttpServerErrorException.class)
    public void tokenCannotBeFetchedFromCodeBecauseOfServerError() throws Exception {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = getProvider();

        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        mockUaaServer.expect(requestTo("http://oidc10.oms.identity.team/oauth/token")).andRespond(withServerError());
        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test(expected = HttpClientErrorException.class)
    public void tokenCannotBeFetchedFromInvalidCode() throws Exception {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = getProvider();

        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        mockUaaServer.expect(requestTo("http://oidc10.oms.identity.team/oauth/token")).andRespond(withBadRequest());
        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    private void addTheUserOnAuth() {
        doAnswer(invocation -> {
            Object e = invocation.getArguments()[0];
            if (e instanceof NewUserAuthenticatedEvent) {
                NewUserAuthenticatedEvent event = (NewUserAuthenticatedEvent) e;
                UaaUser user = event.getUser();
                userDatabase.addUser(user);
            }
            return null;
        }).when(publisher).publishEvent(ArgumentMatchers.any(ApplicationEvent.class));
    }

    @Test
    public void authenticationContainsAMRClaim_fromExternalOIDCProvider() throws Exception {
        addTheUserOnAuth();
        claims.put("amr", Arrays.asList("mfa", "rba"));
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication)xoAuthAuthenticationManager.authenticate(xCodeToken);
        assertThat(authentication.getAuthenticationMethods(), containsInAnyOrder("mfa", "rba", "ext"));
    }

    @Test
    public void test_user_existing_attributes_mapping() throws Exception {
        addTheUserOnAuth();

        claims.put("emailClaim", "test@email.org");
        claims.put("firstName", "first_name");
        claims.put("lastName", "last_name");
        claims.put("phoneNum", "randomNumber");
        attributeMappings.put("email", "emailClaim");
        attributeMappings.put("given_name", "firstName");
        attributeMappings.put("family_name", "lastName");
        attributeMappings.put("phone_number", "phoneNum");
        attributeMappings.put("email_verified", "email_verified");
        config.setStoreCustomAttributes(true);
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication)xoAuthAuthenticationManager.authenticate(xCodeToken);
        UaaUser actualUaaUser = xoAuthAuthenticationManager.getUserDatabase().retrieveUserById(authentication.getPrincipal().getId());
        assertEquals("test@email.org", actualUaaUser.getEmail());
        assertEquals("first_name", actualUaaUser.getGivenName());
        assertEquals("last_name", actualUaaUser.getFamilyName());
        assertEquals("randomNumber", actualUaaUser.getPhoneNumber());
        assertTrue("verified", actualUaaUser.isVerified());
    }

    @Test
    public void email_verified_is_false() throws Exception {
        addTheUserOnAuth();
        claims.put("email_verified", false);
        attributeMappings.put("email_verified", "email_verified");
        config.setStoreCustomAttributes(true);
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication)xoAuthAuthenticationManager.authenticate(xCodeToken);
        UaaUser actualUaaUser = xoAuthAuthenticationManager.getUserDatabase().retrieveUserById(authentication.getPrincipal().getId());
        assertFalse("verified", actualUaaUser.isVerified());
    }

    @Test
    public void email_verified_claim_is_using_a_custom_name() throws Exception {
        addTheUserOnAuth();
        claims.remove("email_verified");
        claims.put("emailVerified", true);
        attributeMappings.put("email_verified", "emailVerified");
        config.setStoreCustomAttributes(true);
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication)xoAuthAuthenticationManager.authenticate(xCodeToken);
        UaaUser actualUaaUser = xoAuthAuthenticationManager.getUserDatabase().retrieveUserById(authentication.getPrincipal().getId());
        assertTrue("verified", actualUaaUser.isVerified());
    }

    @Test
    public void email_verified_mapping_is_not_there() throws Exception {
        addTheUserOnAuth();
        attributeMappings.remove("email_verified");
        config.setStoreCustomAttributes(true);
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication)xoAuthAuthenticationManager.authenticate(xCodeToken);
        UaaUser actualUaaUser = xoAuthAuthenticationManager.getUserDatabase().retrieveUserById(authentication.getPrincipal().getId());
        assertTrue("verified", actualUaaUser.isVerified());
    }

    @Test
    public void email_verified_is_ommitted() throws Exception {
        addTheUserOnAuth();
        claims.remove("email_verified");
        attributeMappings.put("email_verified", "email_verified");
        config.setStoreCustomAttributes(true);
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication)xoAuthAuthenticationManager.authenticate(xCodeToken);
        UaaUser actualUaaUser = xoAuthAuthenticationManager.getUserDatabase().retrieveUserById(authentication.getPrincipal().getId());
        assertFalse("verified", actualUaaUser.isVerified());
    }


    @Test
    public void testDefaultUsernameValueIsSubjectClaim() throws MalformedURLException {
        String contextPathURL = "http://contextPath.url";
        claims.put("iss", UAA_ISSUER_URL);
        String username = "unique_value";
        claims.put("sub", username);
        CompositeToken token = getCompositeAccessToken();
        String idToken = token.getIdTokenValue();
        xCodeToken.setIdToken(idToken);
        xCodeToken.setOrigin(null);
        xCodeToken.setRequestContextPath(contextPathURL);

        XOAuthAuthenticationManager.AuthenticationData externalAuthenticationDetails = xoAuthAuthenticationManager
            .getExternalAuthenticationDetails(xCodeToken);

        assertEquals(username, externalAuthenticationDetails.getUsername());
    }

    @Test
    public void test_custom_user_attributes_are_stored() throws Exception {
        addTheUserOnAuth();

        List<String> managers = Arrays.asList("Sue the Sloth", "Kari the AntEater");
        List<String> costCenter = Arrays.asList("Austin, TX");
        claims.put("managers", managers);
        claims.put("employeeCostCenter", costCenter);
        attributeMappings.put("user.attribute.costCenter", "employeeCostCenter");
        attributeMappings.put("user.attribute.terribleBosses", "managers");
        config.setStoreCustomAttributes(true);
        config.setExternalGroupsWhitelist(Arrays.asList("*"));
        List<String> scopes = SCOPES_LIST;
        claims.put("scope", scopes);
        attributeMappings.put(GROUP_ATTRIBUTE_NAME, "scope");
        mockToken();
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.put("costCenter", costCenter);
        map.put("terribleBosses", managers);
        UaaAuthentication authentication = (UaaAuthentication)xoAuthAuthenticationManager.authenticate(xCodeToken);
        assertEquals(map, authentication.getUserAttributes());
        assertThat(authentication.getExternalGroups(), containsInAnyOrder(scopes.toArray()));
        UserInfo info = new UserInfo()
            .setUserAttributes(map)
            .setRoles(scopes);
        UserInfo actualUserInfo = xoAuthAuthenticationManager.getUserDatabase().getUserInfo(authentication.getPrincipal().getId());
        assertEquals(actualUserInfo.getUserAttributes(), info.getUserAttributes());
        assertThat(actualUserInfo.getRoles(), containsInAnyOrder(info.getRoles().toArray()));

    }

    private void mockToken() throws MalformedURLException {
        String response = getIdTokenResponse();
        mockUaaServer.expect(requestTo("http://oidc10.oms.identity.team/oauth/token"))
            .andExpect(header("Authorization", "Basic " + new String(Base64.encodeBase64("identity:identitysecret".getBytes()))))
            .andExpect(header("Accept", "application/json"))
            .andExpect(content().string(containsString("grant_type=authorization_code")))
            .andExpect(content().string(containsString("code=the_code")))
            .andExpect(content().string(containsString("redirect_uri=http%3A%2F%2Flocalhost%2Fcallback%2Fthe_origin")))
            .andExpect(content().string(containsString(("response_type=id_token"))))
            .andRespond(withStatus(OK).contentType(APPLICATION_JSON).body(response));
    }

    private CompositeToken getCompositeAccessToken() throws MalformedURLException {
        return getCompositeAccessToken(emptyList());
    }

    private CompositeToken getCompositeAccessToken(List<String> removeClaims) throws MalformedURLException {
        removeClaims.stream().forEach(c -> claims.remove(c));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);
        identityProvider = getProvider();

        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        CompositeToken compositeToken = new CompositeToken("accessToken");
        compositeToken.setIdTokenValue(idTokenJwt);
        return compositeToken;
    }

    private String getIdTokenResponse() throws MalformedURLException {
        return JsonUtils.writeValueAsString(getCompositeAccessToken());
    }

    private IdentityProvider<AbstractXOAuthIdentityProviderDefinition> getProvider() throws MalformedURLException {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = new IdentityProvider<>();
        identityProvider.setName("my oidc provider");
        identityProvider.setIdentityZoneId(OriginKeys.UAA);
        config.setAttributeMappings(attributeMappings);

        identityProvider.setConfig(config);
        identityProvider.setOriginKey("puppy");
        return identityProvider;
    }

    private void testTokenHasAuthoritiesFromIdTokenRoles() throws MalformedURLException {
        attributeMappings.put(GROUP_ATTRIBUTE_NAME, "scope");
        mockToken();

        UaaUser uaaUser = xoAuthAuthenticationManager.getUser(xCodeToken, getAuthenticationData(xCodeToken));

        List<String> authorities = uaaUser.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        for(String scope : SCOPES_LIST) {
            assertThat(authorities, hasItem(scope));
        }
    }

}
