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
import org.apache.commons.lang3.RandomStringUtils;
import org.cloudfoundry.identity.uaa.authentication.AccountNotPreCreatedException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalGroupAuthorizationEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.InvitedUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.NewUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.cache.ExpiringUrlCache;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.oauth.*;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeToken;
import org.cloudfoundry.identity.uaa.oauth.token.VerificationKeyResponse;
import org.cloudfoundry.identity.uaa.oauth.token.VerificationKeysListResponse;
import org.cloudfoundry.identity.uaa.provider.*;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.user.*;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
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
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.Collections.emptyList;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ISS;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.entry;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.map;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

public class XOAuthAuthenticationManagerIT {
    public static final String UAA_ORIGIN = "uaa";

    private MockRestServiceServer mockUaaServer;
    private XOAuthAuthenticationManager xoAuthAuthenticationManager;
    private IdentityProviderProvisioning provisioning;
    private InMemoryUaaUserDatabase userDatabase;
    private XOAuthCodeToken xCodeToken;
    private ApplicationEventPublisher publisher;
    private static final String CODE = "the_code";

    private static final String ORIGIN = "the_origin";
    private static final String ISSUER = "cf-app.com";
    private static final String UAA_ISSUER_URL = "http://issuer.url";
    private static final List<String> SCOPES_LIST = Arrays.asList("openid", "some.other.scope", "closedid");

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


    @AfterEach
    public void clearContext() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }


    @BeforeEach
    public void setUp() throws Exception {
        RestTemplateConfig restTemplateConfig = new RestTemplateConfig();
        RestTemplate nonTrustingRestTemplate = restTemplateConfig.nonTrustingRestTemplate();
        RestTemplate trustingRestTemplate = restTemplateConfig.trustingRestTemplate();
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
        ScimGroupExternalMembershipManager externalMembershipManager = mock(ScimGroupExternalMembershipManager.class);

        for (String scope : SCOPES_LIST) {
            ScimGroupExternalMember member = new ScimGroupExternalMember();
            member.setDisplayName(scope);
            when(externalMembershipManager.getExternalGroupMapsByExternalGroup(eq(scope), anyString(), anyString()))
                    .thenReturn(Collections.singletonList(member));
        }

        userDatabase = new InMemoryUaaUserDatabase(Collections.emptySet());
        publisher = mock(ApplicationEventPublisher.class);
        tokenEndpointBuilder = mock(TokenEndpointBuilder.class);
        when(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get())).thenReturn(UAA_ISSUER_URL);
        OidcMetadataFetcher oidcMetadataFetcher = new OidcMetadataFetcher(
                new ExpiringUrlCache(Duration.ofMinutes(2), new TimeServiceImpl(), 10),
                trustingRestTemplate,
                nonTrustingRestTemplate
        );
        xoAuthProviderConfigurator = spy(
                new XOAuthProviderConfigurator(
                        provisioning,
                        oidcMetadataFetcher
                )
        );
        xoAuthAuthenticationManager = spy(new XOAuthAuthenticationManager(xoAuthProviderConfigurator, trustingRestTemplate, nonTrustingRestTemplate, tokenEndpointBuilder, new KeyInfoService(UAA_ISSUER_URL)));
        xoAuthAuthenticationManager.setUserDatabase(userDatabase);
        xoAuthAuthenticationManager.setExternalMembershipManager(externalMembershipManager);
        xoAuthAuthenticationManager.setApplicationEventPublisher(publisher);
        xoAuthAuthenticationManager.setTokenEndpointBuilder(tokenEndpointBuilder);
        xCodeToken = new XOAuthCodeToken(CODE, ORIGIN, "http://localhost/callback/the_origin");
        claims = map(
                entry("sub", "12345"),
                entry("preferred_username", "marissa"),
                entry("origin", UAA_ORIGIN),
                entry("iss", "http://localhost/oauth/token"),
                entry("given_name", "Marissa"),
                entry("client_id", "client"),
                entry("aud", Arrays.asList("identity", "another_trusted_client")),
                entry("zid", "uaa"),
                entry("user_id", "12345"),
                entry("azp", "client"),
                entry("scope", Collections.singletonList("openid")),
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
                .setAuthUrl(new URL("http://localhost/oauth/authorize"))
                .setTokenUrl(new URL("http://localhost/oauth/token"))
                .setIssuer("http://localhost/oauth/token")
                .setShowLinkText(true)
                .setLinkText("My OIDC Provider")
                .setRelyingPartyId("identity")
                .setRelyingPartySecret("identitysecret")
                .setUserInfoUrl(new URL("http://localhost/userinfo"))
                .setTokenKey(PUBLIC_KEY);
        config.setExternalGroupsWhitelist(
                Collections.singletonList(
                        "*"
                )
        );

        mockUaaServer = MockRestServiceServer.createServer(nonTrustingRestTemplate);

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
        assertThrowsWithMessageThat(IllegalArgumentException.class, () -> {
                    xoAuthAuthenticationManager.getResponseType(new AbstractXOAuthIdentityProviderDefinition() {
                        @Override
                        public URL getAuthUrl() {
                            return super.getAuthUrl();
                        }
                    });
                },
                is("Unknown type for provider."));
    }

    @Test
    public void verify_hmac_256_signature() throws Exception {
        String key = "key";
        String data = "data";
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);
        byte[] hmacData = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        assertThat(new String(Base64.encodeBase64URLSafe(hmacData)), equalTo(xoAuthAuthenticationManager.hmacSignAndEncode(data, key)));
    }

    @Test
    public void test_authManager_origin_is_thread_safe() throws Exception {
        CountDownLatch countDownLatchA = new CountDownLatch(1);
        CountDownLatch countDownLatchB = new CountDownLatch(1);

        final String[] thread1Origin = new String[1];
        final String[] thread2Origin = new String[1];
        Thread thread1 = new Thread() {
            @Override
            public void run() {
                xoAuthAuthenticationManager.setOrigin("a");
                resumeThread2();
                pauseThread1();
                thread1Origin[0] = xoAuthAuthenticationManager.getOrigin();
            }

            private void resumeThread2() {
                countDownLatchB.countDown();
            }

            private void pauseThread1() {
                try {
                    countDownLatchA.await();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        };

        Thread thread2 = new Thread() {
            @Override
            public void run() {
                pauseThread2();
                xoAuthAuthenticationManager.setOrigin("b");
                resumeThread1();

                thread2Origin[0] = xoAuthAuthenticationManager.getOrigin();
            }

            private void resumeThread1() {
                countDownLatchA.countDown();
            }

            private void pauseThread2() {
                try {
                    countDownLatchB.await();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        };

        thread2.start();
        thread1.start();

        thread1.join();
        thread2.join();

        assertThat(thread1Origin[0], is("a"));
        assertThat(thread2Origin[0], is("b"));
    }

    @Test
    public void when_a_null_id_token_is_provided_resolveOriginProvider_should_throw_a_jwt_validation_exception() {
        assertThrowsWithMessageThat(InsufficientAuthenticationException.class,
                () -> xoAuthAuthenticationManager.resolveOriginProvider(null),
                is("Unable to decode expected id_token"));
    }

    @Test
    public void unable_to_resolve_to_single_provider() {
        CompositeToken token = getCompositeAccessToken();
        xCodeToken = new XOAuthCodeToken(null, null, null, token.getIdTokenValue(), null, null);
        String zoneId = IdentityZoneHolder.get().getId();
        when(provisioning.retrieveAll(eq(true), eq(zoneId))).thenReturn(emptyList());

        assertThrowsWithMessageThat(InsufficientAuthenticationException.class,
                () -> xoAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken),
                is(String.format("Unable to map issuer, %s , to a single registered provider", claims.get(ISS)))
        );
    }

    @Test
    public void issuer_missing_in_id_token() {
        getProvider();
        CompositeToken token = getCompositeAccessToken(Collections.singletonList(ISS));
        xCodeToken = new XOAuthCodeToken(null, null, null, token.getIdTokenValue(), null, null);

        assertThrowsWithMessageThat(InsufficientAuthenticationException.class,
                () -> xoAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken),
                is(String.format("Issuer is missing in id_token"))
        );
    }

    @Test
    public void origin_is_resolved_based_on_issuer_and_id_token() {
        CompositeToken token = getCompositeAccessToken();
        xCodeToken = new XOAuthCodeToken(null, null, null, token.getIdTokenValue(), null, null);
        when(provisioning.retrieveAll(eq(true), anyString())).thenReturn(Collections.singletonList(getProvider()));
        //perform test
        xoAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken);

        ArgumentCaptor<String> idTokenCaptor = ArgumentCaptor.forClass(String.class);
        verify(xoAuthAuthenticationManager, times(1)).resolveOriginProvider(idTokenCaptor.capture());
        verify(provisioning, never()).retrieveByOrigin(anyString(), anyString());
        verify(xoAuthProviderConfigurator, times(1)).retrieveByIssuer(eq("http://localhost/oauth/token"), anyString());
        assertEquals(token.getIdTokenValue(), idTokenCaptor.getValue());
    }

    @Test
    public void when_unable_to_find_an_idp_that_matches_the_id_token_issuer() {

        String issuerURL = "http://issuer.url";
        when(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get())).thenReturn("http://another-issuer.url");
        claims.put("iss", issuerURL);
        CompositeToken token = getCompositeAccessToken();

        assertThrows(InsufficientAuthenticationException.class, () -> xoAuthAuthenticationManager.resolveOriginProvider(token.getIdTokenValue()));
    }

    @Test
    public void when_exchanging_an_id_token_retrieved_from_the_internal_uaa_idp_for_an_access_token_then_auth_data_should_contain_oidc_sub_claim() {
        when(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get())).thenReturn("http://localhost/oauth/token");

        when(provisioning.retrieveAll(eq(true), anyString())).thenReturn(new ArrayList<>());

        String username = RandomStringUtils.random(50);
        claims.put("sub", username);
        claims.put("iss", "http://localhost/oauth/token");
        claims.put("origin", UAA_ORIGIN);

        CompositeToken token = getCompositeAccessToken();
        String idToken = token.getIdTokenValue();
        xCodeToken.setIdToken(idToken);
        xCodeToken.setOrigin(null);

        XOAuthAuthenticationManager.AuthenticationData externalAuthenticationDetails = xoAuthAuthenticationManager
                .getExternalAuthenticationDetails(xCodeToken);

        assertThat(username, is(externalAuthenticationDetails.getUsername()));
        assertThat(externalAuthenticationDetails.getClaims().get(ClaimConstants.ORIGIN), is(UAA_ORIGIN));
        assertThat(xoAuthAuthenticationManager.getOrigin(), is(UAA_ORIGIN));
    }

    @ParameterizedTest
    @MethodSource("invalidOrigins")
    public void when_exchanging_an_id_token_issuedby_the_uaa_idp_but_not_uaa_origin(String origin) {
        when(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get())).thenReturn("http://localhost/oauth/token");

        when(provisioning.retrieveAll(eq(true), anyString())).thenReturn(new ArrayList<>());

        String username = RandomStringUtils.random(50);
        claims.put("sub", username);
        claims.put("iss", "http://localhost/oauth/token");
        claims.put("origin", origin);

        CompositeToken token = getCompositeAccessToken();
        String idToken = token.getIdTokenValue();
        xCodeToken.setIdToken(idToken);
        xCodeToken.setOrigin(null);

        assertThrows(InsufficientAuthenticationException.class, () -> xoAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken));
    }

    @Test
    public void when_exchanging_an_id_token_retrieved_by_uaa_via_an_oidc_idp_for_an_access_token_origin_should_be_kept() {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> idpProvider = getProvider();
        when(provisioning.retrieveAll(eq(true), anyString())).thenReturn(Collections.singletonList(idpProvider));

        String username = RandomStringUtils.random(50);
        claims.put("sub", username);
        claims.put("iss", UAA_ISSUER_URL);
        claims.put("origin", idpProvider.getOriginKey());

        CompositeToken token = getCompositeAccessToken();
        String idToken = token.getIdTokenValue();
        xCodeToken.setIdToken(idToken);
        xCodeToken.setOrigin(null);


        XOAuthAuthenticationManager.AuthenticationData externalAuthenticationDetails = xoAuthAuthenticationManager
                .getExternalAuthenticationDetails(xCodeToken);

        assertThat(username, is(externalAuthenticationDetails.getUsername()));
        assertThat(externalAuthenticationDetails.getClaims().get(ClaimConstants.ORIGIN), is(idpProvider.getOriginKey()));
        assertThat(xoAuthAuthenticationManager.getOrigin(), is(idpProvider.getOriginKey()));
    }

    @Test
    public void when_exchanging_an_id_token_retrieved_by_uaa_via_an_registered_oidc_idp_for_an_access_token_origin_should_be_taken_from_token() {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> idpProvider = getProvider();
        idpProvider.setType(OriginKeys.OIDC10);
        idpProvider.getConfig().setIssuer(UAA_ISSUER_URL);
        when(provisioning.retrieveAll(eq(true), anyString())).thenReturn(Collections.singletonList(idpProvider));

        String username = RandomStringUtils.random(50);
        claims.put("sub", username);
        claims.put("iss", UAA_ISSUER_URL);
        claims.put("origin", OriginKeys.UAA);

        CompositeToken token = getCompositeAccessToken();
        String idToken = token.getIdTokenValue();
        xCodeToken.setIdToken(idToken);
        xCodeToken.setOrigin(null);


        XOAuthAuthenticationManager.AuthenticationData externalAuthenticationDetails = xoAuthAuthenticationManager
                .getExternalAuthenticationDetails(xCodeToken);

        assertThat(username, is(externalAuthenticationDetails.getUsername()));
        assertThat(externalAuthenticationDetails.getClaims().get(ClaimConstants.ORIGIN), is(OriginKeys.UAA));
        assertThat(xoAuthAuthenticationManager.getOrigin(), is(idpProvider.getOriginKey()));
    }

    @Test
    public void when_exchanging_an_id_token_retrieved_by_an_external_oidc_idp_for_an_access_token_then_auth_data_should_contain_oidc_sub_claim() {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> idpProvider = getProvider();
        when(provisioning.retrieveAll(eq(true), anyString())).thenReturn(Collections.singletonList(idpProvider));

        String username = RandomStringUtils.random(50);
        claims.put("sub", username);
        claims.put("iss", idpProvider.getConfig().getIssuer());
        claims.put("origin", idpProvider.getOriginKey());

        CompositeToken token = getCompositeAccessToken();
        String idToken = token.getIdTokenValue();
        xCodeToken.setIdToken(idToken);
        xCodeToken.setOrigin(null);


        XOAuthAuthenticationManager.AuthenticationData externalAuthenticationDetails = xoAuthAuthenticationManager
                .getExternalAuthenticationDetails(xCodeToken);

        assertThat(username, is(externalAuthenticationDetails.getUsername()));
        assertThat(externalAuthenticationDetails.getClaims().get(ClaimConstants.ORIGIN), is(idpProvider.getOriginKey()));
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
    public void clientAuthInBody_is_used() {
        config.setClientAuthInBody(true);
        mockUaaServer.expect(requestTo(config.getTokenUrl().toString()))
                .andExpect(request -> assertThat("Check Auth header not present", request.getHeaders().get("Authorization"), nullValue()))
                .andExpect(content().string(containsString("client_id=" + config.getRelyingPartyId())))
                .andExpect(content().string(containsString("client_secret=" + config.getRelyingPartySecret())))
                .andRespond(withStatus(OK).contentType(APPLICATION_JSON).body(getIdTokenResponse()));
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = getProvider();
        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        xoAuthAuthenticationManager.getClaimsFromToken(xCodeToken, config);

        mockUaaServer.verify();
    }

    @Test
    public void idToken_In_Redirect_Should_Use_it() {
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
        verify(publisher, times(3)).publishEvent(userArgumentCaptor.capture());
        assertEquals(3, userArgumentCaptor.getAllValues().size());
        NewUserAuthenticatedEvent event = (NewUserAuthenticatedEvent) userArgumentCaptor.getAllValues().get(0);

        assertUserCreated(event);
    }

    @Test
    public void exchangeExternalCodeForIdToken_andCreateShadowUser() {
        mockToken();
        addTheUserOnAuth();

        xoAuthAuthenticationManager.authenticate(xCodeToken);

        mockUaaServer.verify();

        ArgumentCaptor<ApplicationEvent> userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(publisher, times(3)).publishEvent(userArgumentCaptor.capture());
        assertEquals(3, userArgumentCaptor.getAllValues().size());
        NewUserAuthenticatedEvent event = (NewUserAuthenticatedEvent) userArgumentCaptor.getAllValues().get(0);

        assertUserCreated(event);
    }

    @Test
    public void test_single_key_response() throws Exception {
        configureTokenKeyResponse(
                "http://localhost/token_key",
                PRIVATE_KEY,
                "correctKey",
                false);
        addTheUserOnAuth();
        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test
    public void test_single_key_response_without_value() throws Exception {
        String json = getKeyJson(PRIVATE_KEY, "correctKey", false);
        Map<String, Object> map = JsonUtils.readValue(json, new TypeReference<Map<String, Object>>() {
        });
        map.remove("value");
        json = JsonUtils.writeValueAsString(map);
        configureTokenKeyResponse("http://localhost/token_key", json);
        addTheUserOnAuth();
        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test
    public void test_multi_key_response_without_value() throws Exception {
        String jsonValid = getKeyJson(PRIVATE_KEY, "correctKey", false);
        String jsonInvalid = getKeyJson(invalidRsaSigningKey, "invalidKey", false);
        Map<String, Object> mapValid = JsonUtils.readValue(jsonValid, new TypeReference<Map<String, Object>>() {
        });
        Map<String, Object> mapInvalid = JsonUtils.readValue(jsonInvalid, new TypeReference<Map<String, Object>>() {
        });
        mapValid.remove("value");
        mapInvalid.remove("value");
        String json = JsonUtils.writeValueAsString(new JsonWebKeySet<>(Arrays.asList(new JsonWebKey(mapInvalid), new JsonWebKey(mapValid))));
        configureTokenKeyResponse("http://localhost/token_key", json);
        addTheUserOnAuth();
        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test
    public void test_multi_key_all_invalid() throws Exception {
        String jsonInvalid = getKeyJson(invalidRsaSigningKey, "invalidKey", false);
        String jsonInvalid2 = getKeyJson(invalidRsaSigningKey, "invalidKey2", false);
        Map<String, Object> mapInvalid = JsonUtils.readValue(jsonInvalid, new TypeReference<Map<String, Object>>() {
        });
        Map<String, Object> mapInvalid2 = JsonUtils.readValue(jsonInvalid2, new TypeReference<Map<String, Object>>() {
        });
        String json = JsonUtils.writeValueAsString(new JsonWebKeySet<>(Arrays.asList(new JsonWebKey(mapInvalid), new JsonWebKey(mapInvalid2))));
        assertTrue(json.contains("\"invalidKey\""));
        assertTrue(json.contains("\"invalidKey2\""));
        configureTokenKeyResponse("http://localhost/token_key", json);
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
                "http://localhost/token_key",
                PRIVATE_KEY,
                "correctKey",
                true);
        addTheUserOnAuth();
        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test
    public void doesNotCreateShadowUserAndFailsAuthentication_IfAddShadowUserOnLoginIsFalse() {
        config.setAddShadowUserOnLogin(false);
        mockToken();

        assertThrows(AccountNotPreCreatedException.class, () -> xoAuthAuthenticationManager.authenticate(xCodeToken));

    }

    @Test
    public void rejectTokenWithInvalidSignature() {
        mockToken();

        config.setTokenKey("WRONG_KEY");

        assertThrows(InvalidTokenException.class, () -> xoAuthAuthenticationManager.authenticate(xCodeToken));
    }

    @Test
    public void rejectTokenWithInvalidSignatureAccordingToTokenKeyEndpoint() throws Exception {
        configureTokenKeyResponse("http://localhost/token_key", invalidRsaSigningKey, "wrongKey");

        assertThrows(InvalidTokenException.class, () -> xoAuthAuthenticationManager.authenticate(xCodeToken));
    }

    @Test
    public void rejectTokenWithInvalidIssuer() {
        claims.put("iss", "http://wrong.issuer/");
        mockToken();

        assertThrows(InvalidTokenException.class, () -> xoAuthAuthenticationManager.authenticate(xCodeToken));
    }

    @Test
    public void rejectExpiredToken() {
        claims.put("exp", Instant.now().getEpochSecond() - 1);
        mockToken();

        assertThrows(InvalidTokenException.class, () -> xoAuthAuthenticationManager.authenticate(xCodeToken));
    }

    @Test
    public void rejectWrongAudience() {
        claims.put("aud", Arrays.asList("another_client", "a_complete_stranger"));
        mockToken();

        assertThrows(InvalidTokenException.class, () -> xoAuthAuthenticationManager.authenticate(xCodeToken));
    }

    @Test
    public void updateShadowUser_IfAlreadyExists() {
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
        verify(publisher, times(2)).publishEvent(userArgumentCaptor.capture());
        assertEquals(2, userArgumentCaptor.getAllValues().size());
        ExternalGroupAuthorizationEvent event = (ExternalGroupAuthorizationEvent) userArgumentCaptor.getAllValues().get(0);

        UaaUser uaaUser = event.getUser();
        assertEquals("Marissa", uaaUser.getGivenName());
        assertEquals("Bloggs", uaaUser.getFamilyName());
        assertEquals("marissa@bloggs.com", uaaUser.getEmail());
        assertEquals("the_origin", uaaUser.getOrigin());
        assertEquals("1234567890", uaaUser.getPhoneNumber());
        assertEquals("12345", uaaUser.getUsername());
        assertEquals(OriginKeys.UAA, uaaUser.getZoneId());
    }

    @Test
    public void invitedUser_becomesVerifiedOnAccept() {
        setUpInvitedUser();

        claims.remove("preferred_username");
        claims.put("preferred_username", "marissa@bloggs.com");
        mockToken();

        xoAuthAuthenticationManager.authenticate(xCodeToken);
        mockUaaServer.verify();

        ArgumentCaptor<ApplicationEvent> userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(publisher, times(3)).publishEvent(userArgumentCaptor.capture());
        assertEquals(3, userArgumentCaptor.getAllValues().size());
        assertThat(userArgumentCaptor.getAllValues().get(0), instanceOf(InvitedUserAuthenticatedEvent.class));

        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    public void loginAndValidateSignatureUsingTokenKeyEndpoint() throws Exception {
        config.setTokenKeyUrl(new URL("http://localhost/token_key"));
        config.setTokenKey(null);

        KeyInfo key = KeyInfoBuilder.build("correctKey", PRIVATE_KEY, UAA_ISSUER_URL);
        VerificationKeyResponse verificationKeyResponse = TokenKeyEndpoint.getVerificationKeyResponse(key);
        String response = JsonUtils.writeValueAsString(verificationKeyResponse);

        mockToken();
        mockUaaServer.expect(requestTo("http://localhost/token_key"))
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
    public void authenticatedUser_hasAuthoritiesFromListOfIDTokenRoles() {
        claims.put("scope", SCOPES_LIST);
        config.setExternalGroupsWhitelist(Collections.emptyList());
        testTokenHasAuthoritiesFromIdTokenRoles();
    }

    @Test
    public void authenticatedUser_hasAuthoritiesFromCommaSeparatedStringOfIDTokenRoles() {
        claims.put("scope", "openid,some.other.scope,closedid");
        testTokenHasAuthoritiesFromIdTokenRoles();
    }

    @Test
    public void authenticatedUser_hasConfigurableUsernameField() {
        attributeMappings.put(USER_NAME_ATTRIBUTE_NAME, "username");

        claims.remove("preferred_username");
        claims.put("username", "marissa");
        mockToken();

        UaaUser uaaUser = xoAuthAuthenticationManager.getUser(xCodeToken, xoAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken));

        assertThat(uaaUser.getUsername(), is("marissa"));
    }

    @Test
    public void username_defaults_to_subject() {
        claims.remove("preferred_username");
        mockToken();
        UaaUser uaaUser = xoAuthAuthenticationManager.getUser(xCodeToken, xoAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken));
        assertThat(uaaUser.getUsername(), is("12345"));
    }

    @Test
    public void missing_user_name_throws_auth_exception() {
        claims.remove("preferred_username");
        claims.remove("sub");
        mockToken();

        assertThrowsWithMessageThat(InsufficientAuthenticationException.class,
                () -> xoAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken),
                is(String.format("Unable to map claim to a username"))
        );
    }

    @Test
    public void getUserWithNullEmail() {
        claims.put("email", null);
        mockToken();
        UaaUser user = xoAuthAuthenticationManager.getUser(xCodeToken, xoAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken));

        assertEquals("12345@user.from.the_origin.cf", user.getEmail());
    }

    @Test
    public void testGetUserSetsTheRightOrigin() {
        xoAuthAuthenticationManager.getUser(xCodeToken, xoAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken));
        assertEquals(ORIGIN, xoAuthAuthenticationManager.getOrigin());

        XOAuthCodeToken otherToken = new XOAuthCodeToken(CODE, "other_origin", "http://localhost/callback/the_origin");
        xoAuthAuthenticationManager.getUser(otherToken, xoAuthAuthenticationManager.getExternalAuthenticationDetails(otherToken));
        assertEquals("other_origin", xoAuthAuthenticationManager.getOrigin());
    }

    @Test
    public void testGetUserIssuerOverrideNotUsed() {
        mockToken();
        assertNotNull(xoAuthAuthenticationManager.getUser(xCodeToken, xoAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken)));
    }

    @Test
    public void testGetUserIssuerOverrideUsedNoMatch() {
        config.setIssuer(ISSUER);
        mockToken();

        assertThrows(InvalidTokenException.class,
                () -> xoAuthAuthenticationManager.getUser(
                        xCodeToken,
                        xoAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken)
                )
        );
    }

    @Test
    public void testGetUserIssuerOverrideUsedMatch() {
        config.setIssuer(ISSUER);
        claims.remove("iss");
        claims.put("iss", ISSUER);
        mockToken();
        assertNotNull(xoAuthAuthenticationManager.getUser(xCodeToken, xoAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken)));
    }

    @Test
    public void test_authentication_context_transfers_to_authentication() {
        addTheUserOnAuth();
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication) xoAuthAuthenticationManager.authenticate(xCodeToken);
        assertNotNull(authentication);
        assertNotNull(authentication.getAuthContextClassRef());
        assertThat(authentication.getAuthContextClassRef(), containsInAnyOrder("urn:oasis:names:tc:SAML:2.0:ac:classes:Password"));
    }

    @Test
    public void test_authentication_context_when_missing() {
        addTheUserOnAuth();
        claims.remove(ClaimConstants.ACR);
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication) xoAuthAuthenticationManager.authenticate(xCodeToken);
        assertNotNull(authentication);
        assertNull(authentication.getAuthContextClassRef());
    }

    @Test
    public void unableToAuthenticate_whenProviderIsNotOIDCOrOAuth() {
        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(MultitenancyFixture.identityProvider("the_origin", "uaa"));
        Authentication authentication = xoAuthAuthenticationManager.authenticate(xCodeToken);
        assertNull(authentication);
    }

    @Test
    public void unableToAuthenticate_whenProviderIsNotFound() {
        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(null);
        Authentication authentication = xoAuthAuthenticationManager.authenticate(xCodeToken);
        assertNull(authentication);
    }

    @Test
    public void tokenCannotBeFetchedFromCodeBecauseOfServerError() {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = getProvider();

        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        mockUaaServer.expect(requestTo("http://localhost/oauth/token")).andRespond(withServerError());

        assertThrows(HttpServerErrorException.class, () -> xoAuthAuthenticationManager.authenticate(xCodeToken));
    }

    @Test
    public void tokenCannotBeFetchedFromInvalidCode() {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = getProvider();

        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        mockUaaServer.expect(requestTo("http://localhost/oauth/token")).andRespond(withBadRequest());

        assertThrows(HttpClientErrorException.class, () -> xoAuthAuthenticationManager.authenticate(xCodeToken));
    }

    @Test
    public void authenticationContainsAMRClaim_fromExternalOIDCProvider() {
        addTheUserOnAuth();
        claims.put("amr", Arrays.asList("mfa", "rba"));
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication) xoAuthAuthenticationManager.authenticate(xCodeToken);
        assertThat(authentication.getAuthenticationMethods(), containsInAnyOrder("mfa", "rba", "ext"));
    }

    @Test
    public void test_user_existing_attributes_mapping() {
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
        UaaAuthentication authentication = (UaaAuthentication) xoAuthAuthenticationManager.authenticate(xCodeToken);
        UaaUser actualUaaUser = xoAuthAuthenticationManager.getUserDatabase().retrieveUserById(authentication.getPrincipal().getId());
        assertEquals("test@email.org", actualUaaUser.getEmail());
        assertEquals("first_name", actualUaaUser.getGivenName());
        assertEquals("last_name", actualUaaUser.getFamilyName());
        assertEquals("randomNumber", actualUaaUser.getPhoneNumber());
        assertTrue("verified", actualUaaUser.isVerified());
    }

    @Test
    public void email_verified_is_false() {
        addTheUserOnAuth();
        claims.put("email_verified", false);
        attributeMappings.put("email_verified", "email_verified");
        config.setStoreCustomAttributes(true);
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication) xoAuthAuthenticationManager.authenticate(xCodeToken);
        UaaUser actualUaaUser = xoAuthAuthenticationManager.getUserDatabase().retrieveUserById(authentication.getPrincipal().getId());
        assertFalse("verified", actualUaaUser.isVerified());
    }

    @Test
    public void email_verified_claim_is_using_a_custom_name() {
        addTheUserOnAuth();
        claims.remove("email_verified");
        claims.put("emailVerified", true);
        attributeMappings.put("email_verified", "emailVerified");
        config.setStoreCustomAttributes(true);
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication) xoAuthAuthenticationManager.authenticate(xCodeToken);
        UaaUser actualUaaUser = xoAuthAuthenticationManager.getUserDatabase().retrieveUserById(authentication.getPrincipal().getId());
        assertTrue("verified", actualUaaUser.isVerified());
    }

    @Test
    public void email_verified_mapping_is_not_there() {
        addTheUserOnAuth();
        attributeMappings.remove("email_verified");
        config.setStoreCustomAttributes(true);
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication) xoAuthAuthenticationManager.authenticate(xCodeToken);
        UaaUser actualUaaUser = xoAuthAuthenticationManager.getUserDatabase().retrieveUserById(authentication.getPrincipal().getId());
        assertTrue("verified", actualUaaUser.isVerified());
    }

    @Test
    public void email_verified_is_ommitted() {
        addTheUserOnAuth();
        claims.remove("email_verified");
        attributeMappings.put("email_verified", "email_verified");
        config.setStoreCustomAttributes(true);
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication) xoAuthAuthenticationManager.authenticate(xCodeToken);
        UaaUser actualUaaUser = xoAuthAuthenticationManager.getUserDatabase().retrieveUserById(authentication.getPrincipal().getId());
        assertFalse("verified", actualUaaUser.isVerified());
    }

    @Test
    public void test_custom_user_attributes_are_stored() {
        addTheUserOnAuth();

        List<String> managers = Arrays.asList("Sue the Sloth", "Kari the AntEater");
        List<String> costCenter = Collections.singletonList("Austin, TX");
        claims.put("managers", managers);
        claims.put("employeeCostCenter", costCenter);
        attributeMappings.put("user.attribute.costCenter", "employeeCostCenter");
        attributeMappings.put("user.attribute.terribleBosses", "managers");
        config.setStoreCustomAttributes(true);
        config.setExternalGroupsWhitelist(Collections.singletonList("*"));
        List<String> scopes = SCOPES_LIST;
        claims.put("scope", scopes);
        attributeMappings.put(GROUP_ATTRIBUTE_NAME, "scope");
        mockToken();
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.put("costCenter", costCenter);
        map.put("terribleBosses", managers);

        UaaAuthentication authentication = (UaaAuthentication) xoAuthAuthenticationManager.authenticate(xCodeToken);

        assertEquals(map, authentication.getUserAttributes());
        assertThat(authentication.getExternalGroups(), containsInAnyOrder(scopes.toArray()));
        UserInfo info = new UserInfo()
                .setUserAttributes(map)
                .setRoles(scopes);
        UserInfo actualUserInfo = xoAuthAuthenticationManager.getUserDatabase().getUserInfo(authentication.getPrincipal().getId());
        assertEquals(actualUserInfo.getUserAttributes(), info.getUserAttributes());
        assertThat(actualUserInfo.getRoles(), containsInAnyOrder(info.getRoles().toArray()));

        UaaUser actualUser = xoAuthAuthenticationManager.getUserDatabase().retrieveUserByName("12345", "the_origin");
        assertThat(actualUser, is(not(nullValue())));
        assertThat(actualUser.getGivenName(), is("Marissa"));
    }

    private void assertUserCreated(NewUserAuthenticatedEvent event) {
        assertNotNull(event);
        UaaUser uaaUser = event.getUser();
        assertNotNull(uaaUser);
        assertEquals("Marissa", uaaUser.getGivenName());
        assertEquals("Bloggs", uaaUser.getFamilyName());
        assertEquals("marissa@bloggs.com", uaaUser.getEmail());
        assertEquals("the_origin", uaaUser.getOrigin());
        assertEquals("1234567890", uaaUser.getPhoneNumber());
        assertEquals("12345", uaaUser.getUsername());
        assertEquals(OriginKeys.UAA, uaaUser.getZoneId());
    }

    private void configureTokenKeyResponse(String keyUrl, String signingKey, String keyId) throws MalformedURLException {
        configureTokenKeyResponse(keyUrl, signingKey, keyId, false);
    }

    private void configureTokenKeyResponse(String keyUrl, String signingKey, String keyId, boolean list) throws MalformedURLException {
        String response = getKeyJson(signingKey, keyId, list);
        configureTokenKeyResponse(keyUrl, response);
    }

    private String getKeyJson(String signingKey, String keyId, boolean list) {
        KeyInfo key = KeyInfoBuilder.build(keyId, signingKey, UAA_ISSUER_URL);
        VerificationKeyResponse keyResponse = TokenKeyEndpoint.getVerificationKeyResponse(key);
        Object verificationKeyResponse = list ? new VerificationKeysListResponse(Collections.singletonList(keyResponse)) : keyResponse;
        return JsonUtils.writeValueAsString(verificationKeyResponse);
    }

    private void configureTokenKeyResponse(String keyUrl, String response) throws MalformedURLException {
        config.setTokenKey(null);
        config.setTokenKeyUrl(new URL(keyUrl));
        mockToken();
        mockUaaServer.expect(requestTo(keyUrl))
                .andExpect(header("Authorization", "Basic " + new String(Base64.encodeBase64("identity:identitysecret".getBytes()))))
                .andExpect(header("Accept", "application/json"))
                .andRespond(withStatus(OK).contentType(APPLICATION_JSON).body(response));
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
        }).when(publisher).publishEvent(any(ApplicationEvent.class));
    }

    private void setUpInvitedUser() {
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
    }

    private void mockToken() {
        String response = getIdTokenResponse();
        mockUaaServer.expect(requestTo("http://localhost/oauth/token"))
                .andExpect(header("Authorization", "Basic " + new String(Base64.encodeBase64("identity:identitysecret".getBytes()))))
                .andExpect(header("Accept", "application/json"))
                .andExpect(content().string(containsString("grant_type=authorization_code")))
                .andExpect(content().string(containsString("code=the_code")))
                .andExpect(content().string(containsString("redirect_uri=http%3A%2F%2Flocalhost%2Fcallback%2Fthe_origin")))
                .andExpect(content().string(containsString(("response_type=id_token"))))
                .andRespond(withStatus(OK).contentType(APPLICATION_JSON).body(response));
    }

    private CompositeToken getCompositeAccessToken() {
        return getCompositeAccessToken(emptyList());
    }

    private CompositeToken getCompositeAccessToken(List<String> removeClaims) {
        removeClaims.stream().forEach(c -> claims.remove(c));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);

        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = getProvider();
        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        CompositeToken compositeToken = new CompositeToken("accessToken");
        compositeToken.setIdTokenValue(idTokenJwt);
        return compositeToken;
    }

    private String getIdTokenResponse() {
        return JsonUtils.writeValueAsString(getCompositeAccessToken());
    }

    private IdentityProvider<AbstractXOAuthIdentityProviderDefinition> getProvider() {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = new IdentityProvider<>();
        identityProvider.setName("my oidc provider");
        identityProvider.setIdentityZoneId(OriginKeys.UAA);
        config.setAttributeMappings(attributeMappings);

        identityProvider.setConfig(config);
        identityProvider.setOriginKey("puppy");
        return identityProvider;
    }

    private void testTokenHasAuthoritiesFromIdTokenRoles() {
        attributeMappings.put(GROUP_ATTRIBUTE_NAME, "scope");
        mockToken();

        UaaUser uaaUser = xoAuthAuthenticationManager.getUser(xCodeToken, xoAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken));

        List<String> authorities = uaaUser.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        for (String scope : SCOPES_LIST) {
            assertThat(authorities, hasItem(scope));
        }
    }
    private static Stream<String> invalidOrigins() {
        return Stream.of("", null);
    }
}
