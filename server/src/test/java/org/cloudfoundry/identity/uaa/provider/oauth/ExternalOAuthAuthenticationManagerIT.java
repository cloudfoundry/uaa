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
import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.TokenKeyEndpoint;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeToken;
import org.cloudfoundry.identity.uaa.oauth.token.VerificationKeyResponse;
import org.cloudfoundry.identity.uaa.oauth.token.VerificationKeysListResponse;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.RawExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.user.InMemoryUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.user.UserInfo;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.util.UaaRandomStringUtil;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.same;
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

class ExternalOAuthAuthenticationManagerIT {
    private static final String UAA_ORIGIN = "uaa";

    private MockRestServiceServer mockUaaServer;
    private ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager;
    private UrlContentCache urlContentCache;
    private IdentityProviderProvisioning provisioning;
    private InMemoryUaaUserDatabase userDatabase;
    private ExternalOAuthCodeToken xCodeToken;
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
    private ExternalOAuthProviderConfigurator externalOAuthProviderConfigurator;
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
    void clearContext() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @BeforeEach
    void setUp() throws Exception {
        RestTemplateConfig restTemplateConfig = RestTemplateConfig.createDefaults();
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
        urlContentCache = spy(new ExpiringUrlCache(Duration.ofMinutes(2), new TimeServiceImpl(), 10));
        OidcMetadataFetcher oidcMetadataFetcher = new OidcMetadataFetcher(
                urlContentCache,
                trustingRestTemplate,
                nonTrustingRestTemplate
        );
        externalOAuthProviderConfigurator = spy(
                new ExternalOAuthProviderConfigurator(
                        provisioning,
                        oidcMetadataFetcher,
                        mock(UaaRandomStringUtil.class))
        );
        externalOAuthAuthenticationManager = spy(new ExternalOAuthAuthenticationManager(externalOAuthProviderConfigurator, trustingRestTemplate, nonTrustingRestTemplate, tokenEndpointBuilder, new KeyInfoService(UAA_ISSUER_URL), oidcMetadataFetcher));
        externalOAuthAuthenticationManager.setUserDatabase(userDatabase);
        externalOAuthAuthenticationManager.setExternalMembershipManager(externalMembershipManager);
        externalOAuthAuthenticationManager.setApplicationEventPublisher(publisher);
        externalOAuthAuthenticationManager.setTokenEndpointBuilder(tokenEndpointBuilder);
        xCodeToken = new ExternalOAuthCodeToken(CODE, ORIGIN, "http://localhost/callback/the_origin");
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
    void get_response_type_for_oauth2() {
        RawExternalOAuthIdentityProviderDefinition signed = new RawExternalOAuthIdentityProviderDefinition();
        signed.setResponseType("signed_request");
        RawExternalOAuthIdentityProviderDefinition code = new RawExternalOAuthIdentityProviderDefinition();
        RawExternalOAuthIdentityProviderDefinition token = new RawExternalOAuthIdentityProviderDefinition();
        token.setResponseType("token");
        OIDCIdentityProviderDefinition oidcIdentityProviderDefinition = new OIDCIdentityProviderDefinition();

        assertEquals("signed_request", externalOAuthAuthenticationManager.getResponseType(signed));
        assertEquals("code", externalOAuthAuthenticationManager.getResponseType(code));
        assertEquals("token", externalOAuthAuthenticationManager.getResponseType(token));
        assertEquals("id_token", externalOAuthAuthenticationManager.getResponseType(oidcIdentityProviderDefinition));
    }

    @Test
    void unknown_config_class() {
        assertThrowsWithMessageThat(IllegalArgumentException.class, () -> {
                    externalOAuthAuthenticationManager.getResponseType(new AbstractExternalOAuthIdentityProviderDefinition() {
                        @Override
                        public URL getAuthUrl() {
                            return super.getAuthUrl();
                        }
                    });
                },
                is("Unknown type for provider."));
    }

    @Test
    void verify_hmac_256_signature() throws Exception {
        String key = "key";
        String data = "data";
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);
        byte[] hmacData = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        assertThat(new String(Base64.encodeBase64URLSafe(hmacData)), equalTo(externalOAuthAuthenticationManager.hmacSignAndEncode(data, key)));
    }

    @Test
    void authManager_origin_is_thread_safe() throws Exception {
        CountDownLatch countDownLatchA = new CountDownLatch(1);
        CountDownLatch countDownLatchB = new CountDownLatch(1);

        final String[] thread1Origin = new String[1];
        final String[] thread2Origin = new String[1];
        Thread thread1 = new Thread() {
            @Override
            public void run() {
                externalOAuthAuthenticationManager.setOrigin("a");
                resumeThread2();
                pauseThread1();
                thread1Origin[0] = externalOAuthAuthenticationManager.getOrigin();
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
                externalOAuthAuthenticationManager.setOrigin("b");
                resumeThread1();

                thread2Origin[0] = externalOAuthAuthenticationManager.getOrigin();
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
    void when_a_null_id_token_is_provided_resolveOriginProvider_should_throw_a_jwt_validation_exception() {
        assertThrowsWithMessageThat(InsufficientAuthenticationException.class,
                () -> externalOAuthAuthenticationManager.resolveOriginProvider(null),
                is("Unable to decode expected id_token"));
    }

    @Test
    void unable_to_resolve_to_single_provider() {
        CompositeToken token = getCompositeAccessToken();
        xCodeToken = new ExternalOAuthCodeToken(null, null, null, token.getIdTokenValue(), null, null);
        String zoneId = IdentityZoneHolder.get().getId();
        when(provisioning.retrieveAll(eq(true), eq(zoneId))).thenReturn(emptyList());

        assertThrowsWithMessageThat(InsufficientAuthenticationException.class,
                () -> externalOAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken),
                is(String.format("Unable to map issuer, %s , to a single registered provider", claims.get(ISS)))
        );
    }

    @Test
    void issuer_missing_in_id_token() {
        getProvider();
        CompositeToken token = getCompositeAccessToken(Collections.singletonList(ISS));
        xCodeToken = new ExternalOAuthCodeToken(null, null, null, token.getIdTokenValue(), null, null);

        assertThrowsWithMessageThat(InsufficientAuthenticationException.class,
                () -> externalOAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken),
                is("Issuer is missing in id_token")
        );
    }

    @Test
    void origin_is_resolved_based_on_issuer_and_id_token() {
        CompositeToken token = getCompositeAccessToken();
        xCodeToken = new ExternalOAuthCodeToken(null, null, null, token.getIdTokenValue(), null, null);
        when(provisioning.retrieveAll(eq(true), anyString())).thenReturn(Collections.singletonList(getProvider()));
        //perform test
        externalOAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken);

        ArgumentCaptor<String> idTokenCaptor = ArgumentCaptor.forClass(String.class);
        verify(externalOAuthAuthenticationManager, times(1)).resolveOriginProvider(idTokenCaptor.capture());
        verify(provisioning, never()).retrieveByOrigin(anyString(), anyString());
        verify(externalOAuthProviderConfigurator, times(1)).retrieveByIssuer(eq("http://localhost/oauth/token"), anyString());
        assertEquals(token.getIdTokenValue(), idTokenCaptor.getValue());
    }

    @Test
    void when_unable_to_find_an_idp_that_matches_the_id_token_issuer() {

        String issuerURL = "http://issuer.url";
        when(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get())).thenReturn("http://another-issuer.url");
        claims.put("iss", issuerURL);
        CompositeToken token = getCompositeAccessToken();

        assertThrows(InsufficientAuthenticationException.class, () -> externalOAuthAuthenticationManager.resolveOriginProvider(token.getIdTokenValue()));
    }

    @Test
    void when_exchanging_an_id_token_retrieved_from_the_internal_uaa_idp_for_an_access_token_then_auth_data_should_contain_oidc_sub_claim() {
        when(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get())).thenReturn("http://localhost/oauth/token");

        when(provisioning.retrieveAll(eq(true), anyString())).thenReturn(new ArrayList<>());

        String username = RandomStringUtils.random(50);
        String userid = UUID.randomUUID().toString();
        claims.put("sub", userid);
        claims.put("user_name", username);
        claims.put("iss", "http://localhost/oauth/token");
        claims.put("origin", UAA_ORIGIN);

        CompositeToken token = getCompositeAccessToken();
        String idToken = token.getIdTokenValue();
        xCodeToken.setIdToken(idToken);
        xCodeToken.setOrigin(null);

        ExternalOAuthAuthenticationManager.AuthenticationData externalAuthenticationDetails = externalOAuthAuthenticationManager
                .getExternalAuthenticationDetails(xCodeToken);

        assertThat(username, is(externalAuthenticationDetails.getUsername()));
        assertThat(externalAuthenticationDetails.getClaims().get(ClaimConstants.ORIGIN), is(UAA_ORIGIN));
        assertThat(externalOAuthAuthenticationManager.getOrigin(), is(UAA_ORIGIN));
    }

    @ParameterizedTest
    @MethodSource("invalidOrigins")
    void when_exchanging_an_id_token_issuedby_the_uaa_idp_but_not_uaa_origin(String origin) {
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

        assertThrows(InsufficientAuthenticationException.class, () -> externalOAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken));
    }

    @Test
    void when_exchanging_an_id_token_retrieved_by_uaa_via_an_oidc_idp_for_an_access_token_origin_should_be_kept() {
        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> idpProvider = getProvider();
        when(provisioning.retrieveAll(eq(true), anyString())).thenReturn(Collections.singletonList(idpProvider));

        String username = RandomStringUtils.random(50);
        String userid = UUID.randomUUID().toString();
        claims.put("sub", userid);
        claims.put("user_name", username);
        claims.put("iss", UAA_ISSUER_URL);
        claims.put("origin", idpProvider.getOriginKey());

        CompositeToken token = getCompositeAccessToken();
        String idToken = token.getIdTokenValue();
        xCodeToken.setIdToken(idToken);
        xCodeToken.setOrigin(null);


        ExternalOAuthAuthenticationManager.AuthenticationData externalAuthenticationDetails = externalOAuthAuthenticationManager
                .getExternalAuthenticationDetails(xCodeToken);

        assertThat(username, is(externalAuthenticationDetails.getUsername()));
        assertThat(externalAuthenticationDetails.getClaims().get(ClaimConstants.ORIGIN), is(idpProvider.getOriginKey()));
        assertThat(externalOAuthAuthenticationManager.getOrigin(), is(idpProvider.getOriginKey()));
    }

    @Test
    void when_exchanging_an_id_token_retrieved_by_uaa_via_an_registered_oidc_idp_for_an_access_token_origin_should_be_taken_from_token() {
        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> idpProvider = getProvider();
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


        ExternalOAuthAuthenticationManager.AuthenticationData externalAuthenticationDetails = externalOAuthAuthenticationManager
                .getExternalAuthenticationDetails(xCodeToken);

        assertThat(username, is(externalAuthenticationDetails.getUsername()));
        assertThat(externalAuthenticationDetails.getClaims().get(ClaimConstants.ORIGIN), is(OriginKeys.UAA));
        assertThat(externalOAuthAuthenticationManager.getOrigin(), is(idpProvider.getOriginKey()));
    }

    @Test
    void when_exchanging_an_id_token_retrieved_by_an_external_oidc_idp_for_an_access_token_then_auth_data_should_contain_oidc_sub_claim() {
        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> idpProvider = getProvider();
        when(provisioning.retrieveAll(eq(true), anyString())).thenReturn(Collections.singletonList(idpProvider));

        String username = RandomStringUtils.random(50);
        claims.put("sub", username);
        claims.put("iss", idpProvider.getConfig().getIssuer());
        claims.put("origin", idpProvider.getOriginKey());

        CompositeToken token = getCompositeAccessToken();
        String idToken = token.getIdTokenValue();
        xCodeToken.setIdToken(idToken);
        xCodeToken.setOrigin(null);


        ExternalOAuthAuthenticationManager.AuthenticationData externalAuthenticationDetails = externalOAuthAuthenticationManager
                .getExternalAuthenticationDetails(xCodeToken);

        assertThat(username, is(externalAuthenticationDetails.getUsername()));
        assertThat(externalAuthenticationDetails.getClaims().get(ClaimConstants.ORIGIN), is(idpProvider.getOriginKey()));
    }

    @Test
    void discoveryURL_is_used() throws MalformedURLException {
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

        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> identityProvider = getProvider();
        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        mockToken();
        addTheUserOnAuth();
        externalOAuthAuthenticationManager.authenticate(xCodeToken);
        verify(externalOAuthProviderConfigurator, atLeast(1)).overlay(eq(config));
        mockUaaServer.verify();

    }

    @Test
    void clientAuthInBody_is_used() {
        config.setClientAuthInBody(true);
        mockUaaServer.expect(requestTo(config.getTokenUrl().toString()))
                .andExpect(request -> assertThat("Check Auth header not present", request.getHeaders().get("Authorization"), nullValue()))
                .andExpect(content().string(containsString("client_id=" + config.getRelyingPartyId())))
                .andExpect(content().string(containsString("client_secret=" + config.getRelyingPartySecret())))
                .andRespond(withStatus(OK).contentType(APPLICATION_JSON).body(getIdTokenResponse()));
        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> identityProvider = getProvider();
        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        externalOAuthAuthenticationManager.getClaimsFromToken(xCodeToken, config);

        mockUaaServer.verify();
    }

    @Test
    void idToken_In_Redirect_Should_Use_it() {
        mockToken();
        addTheUserOnAuth();
        String tokenResponse = getIdTokenResponse();
        String idToken = (String) JsonUtils.readValue(tokenResponse, Map.class).get("id_token");
        xCodeToken.setIdToken(idToken);
        externalOAuthAuthenticationManager.authenticate(xCodeToken);

        verify(externalOAuthAuthenticationManager, times(1)).getClaimsFromToken(same(xCodeToken), any());
        verify(externalOAuthAuthenticationManager, times(1)).getClaimsFromToken(eq(idToken), any());
        verify(externalOAuthAuthenticationManager, never()).getRestTemplate(any());

        ArgumentCaptor<ApplicationEvent> userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(publisher, times(3)).publishEvent(userArgumentCaptor.capture());
        assertEquals(3, userArgumentCaptor.getAllValues().size());
        NewUserAuthenticatedEvent event = (NewUserAuthenticatedEvent) userArgumentCaptor.getAllValues().get(0);

        assertUserCreated(event);
    }

    @Test
    void exchangeExternalCodeForIdToken_andCreateShadowUser() {
        mockToken();
        addTheUserOnAuth();

        externalOAuthAuthenticationManager.authenticate(xCodeToken);

        mockUaaServer.verify();

        ArgumentCaptor<ApplicationEvent> userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(publisher, times(3)).publishEvent(userArgumentCaptor.capture());
        assertEquals(3, userArgumentCaptor.getAllValues().size());
        NewUserAuthenticatedEvent event = (NewUserAuthenticatedEvent) userArgumentCaptor.getAllValues().get(0);

        assertUserCreated(event);
    }

    @Test
    void single_key_response() throws Exception {
        configureTokenKeyResponse(
                "http://localhost/token_key",
                PRIVATE_KEY,
                "correctKey",
                false);
        addTheUserOnAuth();
        externalOAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test
    void single_key_response_without_value() throws Exception {
        String json = getKeyJson(PRIVATE_KEY, "correctKey", false);
        Map<String, Object> map = JsonUtils.readValue(json, new TypeReference<Map<String, Object>>() {
        });
        map.remove("value");
        json = JsonUtils.writeValueAsString(map);
        configureTokenKeyResponse("http://localhost/token_key", json);
        addTheUserOnAuth();
        externalOAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test
    void multi_key_response_without_value() throws Exception {
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
        externalOAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test
    void multi_key_all_invalid() throws Exception {
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
            externalOAuthAuthenticationManager.authenticate(xCodeToken);
            fail("not expected");
        } catch (Exception e) {
            assertTrue(e.getCause() instanceof InvalidSignatureException);
        }
    }

    @Test
    void null_key_invalid() throws Exception {
        String json = new String("");
        configureTokenKeyResponse("http://localhost/token_key", json);
        addTheUserOnAuth();
        try {
            externalOAuthAuthenticationManager.authenticate(xCodeToken);
            fail("not expected");
        } catch (Exception e) {
            assertTrue(e.getCause() instanceof OidcMetadataFetchingException);
        }
    }

    @Test
    void invalid_key() throws Exception {
        String json = new String("{x}");
        configureTokenKeyResponse("http://localhost/token_key", json);
        addTheUserOnAuth();
        try {
            externalOAuthAuthenticationManager.authenticate(xCodeToken);
            fail("not expected");
        } catch (Exception e) {
            assertTrue(e.getCause() instanceof OidcMetadataFetchingException);
        }
    }

    @Test
    void multi_key_response() throws Exception {
        configureTokenKeyResponse(
                "http://localhost/token_key",
                PRIVATE_KEY,
                "correctKey",
                true);
        addTheUserOnAuth();
        externalOAuthAuthenticationManager.authenticate(xCodeToken);
        verify(urlContentCache, times(1)).getUrlContent(any(), any(), any(), any());
    }

    @Test
    void null_key_config_invalid() throws Exception {
        configureTokenKeyResponse(
                "http://localhost/token_key",
                PRIVATE_KEY,
                "correctKey",
                true);
        addTheUserOnAuth();
        config.setTokenKeyUrl(null);
        try {
            externalOAuthAuthenticationManager.authenticate(xCodeToken);
            fail("not expected");
        } catch (Exception e) {
            assertTrue(e instanceof IllegalArgumentException);
        }
    }

    @Test
    void doesNotCreateShadowUserAndFailsAuthentication_IfAddShadowUserOnLoginIsFalse() {
        config.setAddShadowUserOnLogin(false);
        mockToken();

        assertThrows(AccountNotPreCreatedException.class, () -> externalOAuthAuthenticationManager.authenticate(xCodeToken));

    }

    @Test
    void rejectTokenWithInvalidSignature() {
        mockToken();

        config.setTokenKey("WRONG_KEY");

        assertThrows(InvalidTokenException.class, () -> externalOAuthAuthenticationManager.authenticate(xCodeToken));
    }

    @Test
    void rejectTokenWithInvalidSignatureAccordingToTokenKeyEndpoint() throws Exception {
        configureTokenKeyResponse("http://localhost/token_key", invalidRsaSigningKey, "wrongKey");

        assertThrows(InvalidTokenException.class, () -> externalOAuthAuthenticationManager.authenticate(xCodeToken));
    }

    @Test
    void rejectTokenWithInvalidIssuer() {
        claims.put("iss", "http://wrong.issuer/");
        mockToken();

        assertThrows(InvalidTokenException.class, () -> externalOAuthAuthenticationManager.authenticate(xCodeToken));
    }

    @Test
    void rejectExpiredToken() {
        claims.put("exp", Instant.now().getEpochSecond() - 1);
        mockToken();

        assertThrows(InvalidTokenException.class, () -> externalOAuthAuthenticationManager.authenticate(xCodeToken));
    }

    @Test
    void rejectWrongAudience() {
        claims.put("aud", Arrays.asList("another_client", "a_complete_stranger"));
        mockToken();

        assertThrows(InvalidTokenException.class, () -> externalOAuthAuthenticationManager.authenticate(xCodeToken));
    }

    @Test
    void updateShadowUser_IfAlreadyExists() {
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

        externalOAuthAuthenticationManager.authenticate(xCodeToken);
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
    void invitedUser_becomesVerifiedOnAccept() {
        setUpInvitedUser();

        claims.remove("preferred_username");
        claims.put("preferred_username", "marissa@bloggs.com");
        mockToken();

        externalOAuthAuthenticationManager.authenticate(xCodeToken);
        mockUaaServer.verify();

        ArgumentCaptor<ApplicationEvent> userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(publisher, times(3)).publishEvent(userArgumentCaptor.capture());
        assertEquals(3, userArgumentCaptor.getAllValues().size());
        assertThat(userArgumentCaptor.getAllValues().get(0), instanceOf(InvitedUserAuthenticatedEvent.class));

        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void loginAndValidateSignatureUsingTokenKeyEndpoint() throws Exception {
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

        externalOAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test
    void authenticatedUser_hasAuthoritiesFromListOfIDTokenRoles() {
        claims.put("scope", SCOPES_LIST);
        config.setExternalGroupsWhitelist(Collections.emptyList());
        testTokenHasAuthoritiesFromIdTokenRoles();
    }

    @Test
    void authenticatedUser_hasAuthoritiesFromCommaSeparatedStringOfIDTokenRoles() {
        claims.put("scope", "openid,some.other.scope,closedid");
        testTokenHasAuthoritiesFromIdTokenRoles();
    }

    @Test
    void authenticatedUser_hasConfigurableUsernameField() {
        attributeMappings.put(USER_NAME_ATTRIBUTE_NAME, "username");

        claims.remove("preferred_username");
        claims.put("username", "marissa");
        mockToken();

        UaaUser uaaUser = externalOAuthAuthenticationManager.getUser(xCodeToken, externalOAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken));

        assertThat(uaaUser.getUsername(), is("marissa"));
    }

    @Test
    void username_defaults_to_subject() {
        claims.remove("preferred_username");
        mockToken();
        UaaUser uaaUser = externalOAuthAuthenticationManager.getUser(xCodeToken, externalOAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken));
        assertThat(uaaUser.getUsername(), is("12345"));
    }

    @Test
    void missing_user_name_throws_auth_exception() {
        claims.remove("preferred_username");
        claims.remove("sub");
        mockToken();

        assertThrowsWithMessageThat(InsufficientAuthenticationException.class,
                () -> externalOAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken),
                is("Unable to map claim to a username")
        );
    }

    @Test
    void getUserWithNullEmail() {
        claims.put("email", null);
        mockToken();
        UaaUser user = externalOAuthAuthenticationManager.getUser(xCodeToken, externalOAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken));

        assertEquals("12345@user.from.the_origin.cf", user.getEmail());
    }

    @Test
    void testGetUserSetsTheRightOrigin() {
        externalOAuthAuthenticationManager.getUser(xCodeToken, externalOAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken));
        assertEquals(ORIGIN, externalOAuthAuthenticationManager.getOrigin());

        ExternalOAuthCodeToken otherToken = new ExternalOAuthCodeToken(CODE, "other_origin", "http://localhost/callback/the_origin");
        externalOAuthAuthenticationManager.getUser(otherToken, externalOAuthAuthenticationManager.getExternalAuthenticationDetails(otherToken));
        assertEquals("other_origin", externalOAuthAuthenticationManager.getOrigin());
    }

    @Test
    void testGetUserIssuerOverrideNotUsed() {
        mockToken();
        assertNotNull(externalOAuthAuthenticationManager.getUser(xCodeToken, externalOAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken)));
    }

    @Test
    void testGetUserIssuerOverrideUsedNoMatch() {
        config.setIssuer(ISSUER);
        mockToken();

        assertThrows(InvalidTokenException.class,
                () -> externalOAuthAuthenticationManager.getUser(
                        xCodeToken,
                        externalOAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken)
                )
        );
    }

    @Test
    void testGetUserIssuerOverrideUsedMatch() {
        config.setIssuer(ISSUER);
        claims.remove("iss");
        claims.put("iss", ISSUER);
        mockToken();
        assertNotNull(externalOAuthAuthenticationManager.getUser(xCodeToken, externalOAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken)));
    }

    @Test
    void authentication_context_transfers_to_authentication() {
        addTheUserOnAuth();
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication) externalOAuthAuthenticationManager.authenticate(xCodeToken);
        assertNotNull(authentication);
        assertNotNull(authentication.getAuthContextClassRef());
        assertThat(authentication.getAuthContextClassRef(), containsInAnyOrder("urn:oasis:names:tc:SAML:2.0:ac:classes:Password"));
    }

    @Test
    void authentication_context_when_missing() {
        addTheUserOnAuth();
        claims.remove(ClaimConstants.ACR);
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication) externalOAuthAuthenticationManager.authenticate(xCodeToken);
        assertNotNull(authentication);
        assertNull(authentication.getAuthContextClassRef());
    }

    @Test
    void unableToAuthenticate_whenProviderIsNotOIDCOrOAuth() {
        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(MultitenancyFixture.identityProvider("the_origin", "uaa"));
        Authentication authentication = externalOAuthAuthenticationManager.authenticate(xCodeToken);
        assertNull(authentication);
    }

    @Test
    void unableToAuthenticate_whenProviderIsNotFound() {
        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(null);
        Authentication authentication = externalOAuthAuthenticationManager.authenticate(xCodeToken);
        assertNull(authentication);
    }

    @Test
    void tokenCannotBeFetchedFromCodeBecauseOfServerError() {
        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> identityProvider = getProvider();

        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        mockUaaServer.expect(requestTo("http://localhost/oauth/token")).andRespond(withServerError());

        assertThrows(HttpServerErrorException.class, () -> externalOAuthAuthenticationManager.authenticate(xCodeToken));
    }

    @Test
    void tokenCannotBeFetchedFromInvalidCode() {
        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> identityProvider = getProvider();

        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        mockUaaServer.expect(requestTo("http://localhost/oauth/token")).andRespond(withBadRequest());

        assertThrows(HttpClientErrorException.class, () -> externalOAuthAuthenticationManager.authenticate(xCodeToken));
    }

    @Test
    void authenticationContainsAMRClaim_fromExternalOIDCProvider() {
        addTheUserOnAuth();
        claims.put("amr", Arrays.asList("mfa", "rba"));
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication) externalOAuthAuthenticationManager.authenticate(xCodeToken);
        assertThat(authentication.getAuthenticationMethods(), containsInAnyOrder("mfa", "rba", "ext"));
    }

    @Test
    void user_existing_attributes_mapping() {
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
        UaaAuthentication authentication = (UaaAuthentication) externalOAuthAuthenticationManager.authenticate(xCodeToken);
        UaaUser actualUaaUser = externalOAuthAuthenticationManager.getUserDatabase().retrieveUserById(authentication.getPrincipal().getId());
        assertEquals("test@email.org", actualUaaUser.getEmail());
        assertEquals("first_name", actualUaaUser.getGivenName());
        assertEquals("last_name", actualUaaUser.getFamilyName());
        assertEquals("randomNumber", actualUaaUser.getPhoneNumber());
        assertTrue("verified", actualUaaUser.isVerified());
    }

    @Test
    void email_verified_is_false() {
        addTheUserOnAuth();
        claims.put("email_verified", false);
        attributeMappings.put("email_verified", "email_verified");
        config.setStoreCustomAttributes(true);
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication) externalOAuthAuthenticationManager.authenticate(xCodeToken);
        UaaUser actualUaaUser = externalOAuthAuthenticationManager.getUserDatabase().retrieveUserById(authentication.getPrincipal().getId());
        assertFalse("verified", actualUaaUser.isVerified());
    }

    @Test
    void email_verified_claim_is_using_a_custom_name() {
        addTheUserOnAuth();
        claims.remove("email_verified");
        claims.put("emailVerified", true);
        attributeMappings.put("email_verified", "emailVerified");
        config.setStoreCustomAttributes(true);
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication) externalOAuthAuthenticationManager.authenticate(xCodeToken);
        UaaUser actualUaaUser = externalOAuthAuthenticationManager.getUserDatabase().retrieveUserById(authentication.getPrincipal().getId());
        assertTrue("verified", actualUaaUser.isVerified());
    }

    @Test
    void email_verified_mapping_is_not_there() {
        addTheUserOnAuth();
        attributeMappings.remove("email_verified");
        config.setStoreCustomAttributes(true);
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication) externalOAuthAuthenticationManager.authenticate(xCodeToken);
        UaaUser actualUaaUser = externalOAuthAuthenticationManager.getUserDatabase().retrieveUserById(authentication.getPrincipal().getId());
        assertTrue("verified", actualUaaUser.isVerified());
    }

    @Test
    void email_verified_is_ommitted() {
        addTheUserOnAuth();
        claims.remove("email_verified");
        attributeMappings.put("email_verified", "email_verified");
        config.setStoreCustomAttributes(true);
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication) externalOAuthAuthenticationManager.authenticate(xCodeToken);
        UaaUser actualUaaUser = externalOAuthAuthenticationManager.getUserDatabase().retrieveUserById(authentication.getPrincipal().getId());
        assertFalse("verified", actualUaaUser.isVerified());
    }

    @Test
    void custom_user_attributes_are_stored() {
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

        UaaAuthentication authentication = (UaaAuthentication) externalOAuthAuthenticationManager.authenticate(xCodeToken);

        assertEquals(map, authentication.getUserAttributes());
        assertThat(authentication.getExternalGroups(), containsInAnyOrder(scopes.toArray()));
        UserInfo info = new UserInfo()
                .setUserAttributes(map)
                .setRoles(scopes);
        UserInfo actualUserInfo = externalOAuthAuthenticationManager.getUserDatabase().getUserInfo(authentication.getPrincipal().getId());
        assertEquals(actualUserInfo.getUserAttributes(), info.getUserAttributes());
        assertThat(actualUserInfo.getRoles(), containsInAnyOrder(info.getRoles().toArray()));

        UaaUser actualUser = externalOAuthAuthenticationManager.getUserDatabase().retrieveUserByName("12345", "the_origin");
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

        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> identityProvider = getProvider();
        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        CompositeToken compositeToken = new CompositeToken("accessToken");
        compositeToken.setIdTokenValue(idTokenJwt);
        return compositeToken;
    }

    private String getIdTokenResponse() {
        return JsonUtils.writeValueAsString(getCompositeAccessToken());
    }

    private IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> getProvider() {
        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> identityProvider = new IdentityProvider<>();
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

        UaaUser uaaUser = externalOAuthAuthenticationManager.getUser(xCodeToken, externalOAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken));

        List<String> authorities = uaaUser.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        for (String scope : SCOPES_LIST) {
            assertThat(authorities, hasItem(scope));
        }
    }

    private static Stream<String> invalidOrigins() {
        return Stream.of("", null);
    }
}
