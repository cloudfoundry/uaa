package org.cloudfoundry.identity.uaa.provider.oauth;

import com.fasterxml.jackson.core.type.TypeReference;
import com.github.benmanes.caffeine.cache.Ticker;
import com.nimbusds.jose.JWSSigner;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.RandomStringUtils;
import org.cloudfoundry.identity.uaa.authentication.AccountNotPreCreatedException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalGroupAuthorizationEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.InvitedUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.NewUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.cache.StaleUrlCache;
import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.TokenKeyEndpoint;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
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
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.util.UaaRandomStringUtil;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
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
import java.net.URI;
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
import java.util.stream.Stream;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ISS;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.entry;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.map;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.DEFAULT_UAA_URL;
import static org.hamcrest.Matchers.containsString;
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
    private static final String CODE = "the_code";
    private static final String ORIGIN = "the_origin";
    private static final String ISSUER = "cf-app.com";
    private static final String UAA_ISSUER_URL = "http://issuer.url";
    private static final List<String> SCOPES_LIST = Arrays.asList("openid", "some.other.scope", "closedid");

    private static final String PUBLIC_KEY = """
            -----BEGIN PUBLIC KEY-----
            MFswDQYJKoZIhvcNAQEBBQADSgAwRwJAcjAgsHEfrUxeTFwQPb17AkZ2Im4SfZdp
            Y8Ada9pZfxXz1PZSqv9TPTMAzNx+EkzMk2IMYN+uNm1bfDzaxVdz+QIDAQAB
            -----END PUBLIC KEY-----""";

    private static final String PRIVATE_KEY = """
            -----BEGIN RSA PRIVATE KEY-----
            MIIBOQIBAAJAcjAgsHEfrUxeTFwQPb17AkZ2Im4SfZdpY8Ada9pZfxXz1PZSqv9T
            PTMAzNx+EkzMk2IMYN+uNm1bfDzaxVdz+QIDAQABAkBoR39y4rw0/QsY3PKQD5xo
            hYSZCMCmJUI/sFCuECevIFY4h6q9KBP+4Set96f7Bgs9wJWVvCMx/nJ6guHAjsIB
            AiEAywVOoCGIZ2YzARXWYcMRYZ89hxoHh8kZ+QMthRSZieECIQCP/GWQYgyofAQA
            BtM8YwThXEV+S3KtuCn4IAQ89gqdGQIgULBASpZpPyc4OEM0nFBKFTGT46EtwwLj
            RrvDmLPSPiECICQi9FqIQSUH+vkGvX0qXM8ymT5ZMS7oSaA8aNPj7EYBAiEAx5V3
            2JGEulMY3bK1PVGYmtsXF1gq6zbRMoollMCRSMg=
            -----END RSA PRIVATE KEY-----""";

    private static final String INVALID_RSA_SIGNING_KEY = """
            -----BEGIN RSA PRIVATE KEY-----
            MIIBOgIBAAJBAJnlBG4lLmUiHslsKDODfd0MqmGZRNUOhn7eO3cKobsFljUKzRQe
            GB7LYMjPavnKccm6+jWSXutpzfAc9A9wXG8CAwEAAQJADwwdiseH6cuURw2UQLUy
            sVJztmdOG6b375+7IMChX6/cgoF0roCPP0Xr70y1J4TXvFhjcwTgm4RI+AUiIDKw
            gQIhAPQHwHzdYG1639Qz/TCHzuai0ItwVC1wlqKpat+CaqdZAiEAoXFyS7249mRu
            xtwRAvxKMe+eshHvG2le+ZDrM/pz8QcCIQCzmCDpxGL7L7sbCUgFN23l/11Lwdex
            uXKjM9wbsnebwQIgeZIbVovUp74zaQ44xT3EhVwC7ebxXnv3qAkIBMk526sCIDVg
            z1jr3KEcaq9zjNJd9sKBkqpkVSqj8Mv+Amq+YjBA
            -----END RSA PRIVATE KEY-----""";

    private MockRestServiceServer mockUaaServer;
    private ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager;
    private UrlContentCache urlContentCache;
    private IdentityProviderProvisioning provisioning;
    private InMemoryUaaUserDatabase userDatabase;
    private ExternalOAuthCodeToken xCodeToken;
    private ApplicationEventPublisher publisher;

    private Map<String, Object> claims;
    private HashMap<String, Object> attributeMappings;
    private OIDCIdentityProviderDefinition config;
    private JWSSigner signer;
    private Map<String, Object> header;
    private ExternalOAuthProviderConfigurator externalOAuthProviderConfigurator;
    private TokenEndpointBuilder tokenEndpointBuilder;

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
                entry("alg", "RS256"),
                entry("kid", keyName),
                entry("typ", "JWT")
        );
        signer = new KeyInfo(keyName, PRIVATE_KEY, DEFAULT_UAA_URL).getSigner();
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap(keyName, PRIVATE_KEY));

        provisioning = mock(IdentityProviderProvisioning.class);
        IdentityZoneProvisioning identityZoneProvisioning = mock(IdentityZoneProvisioning.class);
        IdentityZoneManager identityZoneManager = new IdentityZoneManagerImpl();
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
        urlContentCache = spy(new StaleUrlCache(Duration.ofMinutes(2), new TimeServiceImpl(), 10, Ticker.systemTicker()));
        OidcMetadataFetcher oidcMetadataFetcher = new OidcMetadataFetcher(
                urlContentCache,
                trustingRestTemplate,
                nonTrustingRestTemplate
        );
        externalOAuthProviderConfigurator = spy(
                new ExternalOAuthProviderConfigurator(
                        provisioning,
                        oidcMetadataFetcher,
                        mock(UaaRandomStringUtil.class),
                        identityZoneProvisioning,
                        identityZoneManager)
        );
        externalOAuthAuthenticationManager = spy(new ExternalOAuthAuthenticationManager(externalOAuthProviderConfigurator, identityZoneManager, trustingRestTemplate, nonTrustingRestTemplate, tokenEndpointBuilder, new KeyInfoService(UAA_ISSUER_URL), oidcMetadataFetcher));
        externalOAuthAuthenticationManager.setUserDatabase(userDatabase);
        externalOAuthAuthenticationManager.setExternalMembershipManager(externalMembershipManager);
        externalOAuthAuthenticationManager.setApplicationEventPublisher(publisher);
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
                .setAuthUrl(URI.create("http://localhost/oauth/authorize").toURL())
                .setTokenUrl(URI.create("http://localhost/oauth/token").toURL())
                .setIssuer("http://localhost/oauth/token")
                .setShowLinkText(true)
                .setLinkText("My OIDC Provider")
                .setRelyingPartyId("identity")
                .setRelyingPartySecret("identitysecret")
                .setUserInfoUrl(URI.create("http://localhost/userinfo").toURL())
                .setTokenKey(PUBLIC_KEY);
        config.setExternalGroupsWhitelist(Collections.singletonList("*"));

        mockUaaServer = MockRestServiceServer.createServer(nonTrustingRestTemplate);
    }

    @Test
    void get_response_type_for_oauth2() {
        RawExternalOAuthIdentityProviderDefinition signed = new RawExternalOAuthIdentityProviderDefinition();
        signed.setResponseType("signed_request");
        RawExternalOAuthIdentityProviderDefinition code = new RawExternalOAuthIdentityProviderDefinition();
        RawExternalOAuthIdentityProviderDefinition token = new RawExternalOAuthIdentityProviderDefinition();
        token.setResponseType("token");
        OIDCIdentityProviderDefinition oidcIdentityProviderDefinition = new OIDCIdentityProviderDefinition();

        assertThat(externalOAuthAuthenticationManager.getResponseType(signed)).isEqualTo("signed_request");
        assertThat(externalOAuthAuthenticationManager.getResponseType(code)).isEqualTo("code");
        assertThat(externalOAuthAuthenticationManager.getResponseType(token)).isEqualTo("token");
        assertThat(externalOAuthAuthenticationManager.getResponseType(oidcIdentityProviderDefinition)).isEqualTo("id_token");
    }

    @Test
    void unknown_config_class() {
        var idp = new AbstractExternalOAuthIdentityProviderDefinition<>() {
            @Override
            public URL getAuthUrl() {
                return super.getAuthUrl();
            }
        };
        assertThatThrownBy(() -> externalOAuthAuthenticationManager.getResponseType(idp))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Unknown type for provider.");
    }

    @Test
    void verify_hmac_256_signature() throws Exception {
        String key = "key";
        String data = "data";
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);
        byte[] hmacData = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        assertThat(new String(Base64.encodeBase64URLSafe(hmacData))).isEqualTo(externalOAuthAuthenticationManager.hmacSignAndEncode(data, key));
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

        assertThat(thread1Origin[0]).isEqualTo("a");
        assertThat(thread2Origin[0]).isEqualTo("b");
    }

    @Test
    void when_a_null_id_token_is_provided_resolveOriginProvider_should_throw_a_jwt_validation_exception() {
        assertThatThrownBy(() -> externalOAuthAuthenticationManager.resolveOriginProvider(null))
                .isInstanceOf(InsufficientAuthenticationException.class)
                .hasMessage("Unable to decode expected id_token");
    }

    @Test
    void unable_to_resolve_to_single_provider() {
        CompositeToken token = getCompositeAccessToken();
        xCodeToken = new ExternalOAuthCodeToken(null, null, null, token.getIdTokenValue(), null, null);
        String zoneId = IdentityZoneHolder.get().getId();
        when(provisioning.retrieveAll(eq(true), eq(zoneId))).thenReturn(emptyList());
        assertThatThrownBy(() -> externalOAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken))
                .isInstanceOf(InsufficientAuthenticationException.class)
                .hasMessage("Unable to map issuer, %s , to a single registered provider".formatted(claims.get(ISS)));
    }

    @Test
    void issuer_missing_in_id_token() {
        getProvider();
        CompositeToken token = getCompositeAccessToken(Collections.singletonList(ISS));
        xCodeToken = new ExternalOAuthCodeToken(null, null, null, token.getIdTokenValue(), null, null);
        assertThatThrownBy(() -> externalOAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken))
                .isInstanceOf(InsufficientAuthenticationException.class)
                .hasMessage("Issuer is missing in id_token");
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
        assertThat(idTokenCaptor.getValue()).isEqualTo(token.getIdTokenValue());
    }

    @Test
    void when_unable_to_find_an_idp_that_matches_the_id_token_issuer() {
        String issuerURL = "http://issuer.url";
        when(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get())).thenReturn("http://another-issuer.url");
        claims.put("iss", issuerURL);
        CompositeToken token = getCompositeAccessToken();

        assertThatExceptionOfType(InsufficientAuthenticationException.class).isThrownBy(() -> externalOAuthAuthenticationManager.resolveOriginProvider(token.getIdTokenValue()));
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

        assertThat(username).isEqualTo(externalAuthenticationDetails.getUsername());
        assertThat(externalAuthenticationDetails.getClaims()).containsEntry(ClaimConstants.ORIGIN, UAA_ORIGIN);
        assertThat(externalOAuthAuthenticationManager.getOrigin()).isEqualTo(UAA_ORIGIN);
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

        assertThatExceptionOfType(InsufficientAuthenticationException.class).isThrownBy(() -> externalOAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken));
    }

    @Test
    void when_exchanging_an_id_token_retrieved_by_uaa_via_an_oidc_idp_for_an_access_token_origin_should_be_kept() {
        IdentityProvider<OIDCIdentityProviderDefinition> idpProvider = getProvider();
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

        assertThat(username).isEqualTo(externalAuthenticationDetails.getUsername());
        assertThat(externalAuthenticationDetails.getClaims()).containsEntry(ClaimConstants.ORIGIN, idpProvider.getOriginKey());
        assertThat(externalOAuthAuthenticationManager.getOrigin()).isEqualTo(idpProvider.getOriginKey());
    }

    @Test
    void when_exchanging_an_id_token_retrieved_by_uaa_via_an_registered_oidc_idp_for_an_access_token_origin_should_be_taken_from_token() {
        IdentityProvider<OIDCIdentityProviderDefinition> idpProvider = getProvider();
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

        assertThat(username).isEqualTo(externalAuthenticationDetails.getUsername());
        assertThat(externalAuthenticationDetails.getClaims()).containsEntry(ClaimConstants.ORIGIN, OriginKeys.UAA);
        assertThat(externalOAuthAuthenticationManager.getOrigin()).isEqualTo(idpProvider.getOriginKey());
    }

    @Test
    void when_exchanging_an_id_token_retrieved_by_an_external_oidc_idp_for_an_access_token_then_auth_data_should_contain_oidc_sub_claim() {
        IdentityProvider<OIDCIdentityProviderDefinition> idpProvider = getProvider();
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

        assertThat(username).isEqualTo(externalAuthenticationDetails.getUsername());
        assertThat(externalAuthenticationDetails.getClaims()).containsEntry(ClaimConstants.ORIGIN, idpProvider.getOriginKey());
    }

    @Test
    void discoveryURL_is_used() throws MalformedURLException {
        URL authUrl = config.getAuthUrl();
        URL tokenUrl = config.getTokenUrl();

        config.setAuthUrl(null);
        config.setTokenUrl(null);
        config.setDiscoveryUrl(URI.create("http://some.discovery.url").toURL());

        Map<String, Object> discoveryContent = new HashMap();
        discoveryContent.put("authorization_endpoint", authUrl.toString());
        discoveryContent.put("token_endpoint", tokenUrl.toString());
        //mandatory but not used
        discoveryContent.put("userinfo_endpoint", "http://localhost/userinfo");
        discoveryContent.put("jwks_uri", "http://localhost/token_keys");
        discoveryContent.put("issuer", "http://localhost/issuer");

        mockUaaServer.expect(requestTo("http://some.discovery.url"))
                .andRespond(withStatus(OK).contentType(APPLICATION_JSON).body(JsonUtils.writeValueAsBytes(discoveryContent)));

        IdentityProvider<OIDCIdentityProviderDefinition> identityProvider = getProvider();
        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        mockToken();
        addTheUserOnAuth();
        externalOAuthAuthenticationManager.authenticate(xCodeToken);
        verify(externalOAuthProviderConfigurator, atLeast(1)).overlay(config);
        mockUaaServer.verify();

    }

    @Test
    void clientAuthInBody_is_used() {
        config.setClientAuthInBody(true);
        mockUaaServer.expect(requestTo(config.getTokenUrl().toString()))
                .andExpect(request -> assertThat(request.getHeaders().get("Authorization")).as("Check Auth header not present").isNull())
                .andExpect(content().string(containsString("client_id=" + config.getRelyingPartyId())))
                .andExpect(content().string(containsString("client_secret=" + config.getRelyingPartySecret())))
                .andRespond(withStatus(OK).contentType(APPLICATION_JSON).body(getIdTokenResponse()));
        IdentityProvider<OIDCIdentityProviderDefinition> identityProvider = getProvider();
        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        externalOAuthAuthenticationManager.getClaimsFromToken(xCodeToken, identityProvider);

        mockUaaServer.verify();
    }

    @Test
    void pkceClientAuthInBody_is_used() {
        config.setClientAuthInBody(true);
        mockUaaServer.expect(requestTo(config.getTokenUrl().toString()))
                .andExpect(request -> assertThat(request.getHeaders().get("Authorization")).as("Check Auth header not present").isNull())
                .andExpect(content().string(containsString("client_id=" + config.getRelyingPartyId())))
                .andRespond(withStatus(OK).contentType(APPLICATION_JSON).body(getIdTokenResponse()));
        IdentityProvider<OIDCIdentityProviderDefinition> identityProvider = getProvider();
        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        config.setRelyingPartySecret(null);
        RequestAttributes attributes = new ServletRequestAttributes(new MockHttpServletRequest());
        attributes.setAttribute(SessionUtils.codeVerifierParameterAttributeKeyForIdp("uaa"), "code_verifier", RequestAttributes.SCOPE_SESSION);
        RequestContextHolder.setRequestAttributes(attributes);

        Map<String, Object> idToken = externalOAuthAuthenticationManager.getClaimsFromToken(xCodeToken, identityProvider);
        assertThat(idToken).isNotNull();

        mockUaaServer.verify();
    }

    @Test
    void pkceWithJwtClientAuthInBody_is_used() {
        config.setClientAuthInBody(true);
        mockUaaServer.expect(requestTo(config.getTokenUrl().toString()))
                .andExpect(request -> assertThat(request.getHeaders().get("Authorization")).as("Check Auth header not present").isNull())
                .andExpect(content().string(containsString("client_id=" + config.getRelyingPartyId())))
                .andRespond(withStatus(OK).contentType(APPLICATION_JSON).body(getIdTokenResponse()));
        IdentityProvider<OIDCIdentityProviderDefinition> identityProvider = getProvider();
        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        config.setRelyingPartySecret(null);
        config.setJwtClientAuthentication(new HashMap<>());
        RequestAttributes attributes = new ServletRequestAttributes(new MockHttpServletRequest());
        attributes.setAttribute(SessionUtils.codeVerifierParameterAttributeKeyForIdp("uaa"), "code_verifier", RequestAttributes.SCOPE_SESSION);
        RequestContextHolder.setRequestAttributes(attributes);

        Map<String, Object> idToken = externalOAuthAuthenticationManager.getClaimsFromToken(xCodeToken, identityProvider);
        assertThat(idToken).isNotNull();

        mockUaaServer.verify();
    }

    @Test
    void additionalParameterClientAuthInBodyIsUsed() {
        config.setClientAuthInBody(true);
        config.setAdditionalAuthzParameters(Map.of("token_format", "opaque"));
        mockUaaServer.expect(requestTo(config.getTokenUrl().toString()))
                .andExpect(request -> assertThat(request.getHeaders().get("Authorization")).as("Check Auth header not present").isNull())
                .andExpect(content().string(containsString("token_format=opaque")))
                .andExpect(content().string(containsString("client_id=" + config.getRelyingPartyId())))
                .andRespond(withStatus(OK).contentType(APPLICATION_JSON).body(getIdTokenResponse()));
        IdentityProvider<OIDCIdentityProviderDefinition> identityProvider = getProvider();
        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);
        Map<String, Object> idToken = externalOAuthAuthenticationManager.getClaimsFromToken(xCodeToken, identityProvider);
        assertThat(idToken).isNotNull();

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
        assertThat(userArgumentCaptor.getAllValues()).hasSize(3);
        NewUserAuthenticatedEvent event = (NewUserAuthenticatedEvent) userArgumentCaptor.getAllValues().getFirst();

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
        assertThat(userArgumentCaptor.getAllValues()).hasSize(3);
        NewUserAuthenticatedEvent event = (NewUserAuthenticatedEvent) userArgumentCaptor.getAllValues().getFirst();

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
        Map<String, Object> map = JsonUtils.readValue(json, new TypeReference<>() {
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
        String jsonInvalid = getKeyJson(INVALID_RSA_SIGNING_KEY, "invalidKey", false);
        Map<String, Object> mapValid = JsonUtils.readValue(jsonValid, new TypeReference<>() {
        });
        Map<String, Object> mapInvalid = JsonUtils.readValue(jsonInvalid, new TypeReference<>() {
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
        String jsonInvalid = getKeyJson(INVALID_RSA_SIGNING_KEY, "invalidKey", false);
        String jsonInvalid2 = getKeyJson(INVALID_RSA_SIGNING_KEY, "invalidKey2", false);
        Map<String, Object> mapInvalid = JsonUtils.readValue(jsonInvalid, new TypeReference<>() {
        });
        Map<String, Object> mapInvalid2 = JsonUtils.readValue(jsonInvalid2, new TypeReference<>() {
        });
        String json = JsonUtils.writeValueAsString(new JsonWebKeySet<>(Arrays.asList(new JsonWebKey(mapInvalid), new JsonWebKey(mapInvalid2))));
        assertThat(json).contains("\"invalidKey\"", "\"invalidKey2\"");
        configureTokenKeyResponse("http://localhost/token_key", json);
        addTheUserOnAuth();
        assertThatThrownBy(() -> externalOAuthAuthenticationManager.authenticate(xCodeToken))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void null_key_invalid() throws Exception {
        String json = "";
        configureTokenKeyResponse("http://localhost/token_key", json);
        addTheUserOnAuth();
        assertThatThrownBy(() -> externalOAuthAuthenticationManager.authenticate(xCodeToken))
                .isInstanceOf(RuntimeException.class)
                .hasCauseInstanceOf(OidcMetadataFetchingException.class);
    }

    @Test
    void invalid_key() throws Exception {
        String json = new String("{x}");
        configureTokenKeyResponse("http://localhost/token_key", json);
        addTheUserOnAuth();
        assertThatThrownBy(() -> externalOAuthAuthenticationManager.authenticate(xCodeToken))
                .isInstanceOf(RuntimeException.class)
                .hasCauseInstanceOf(OidcMetadataFetchingException.class);
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
            assertThat(e).isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void doesNotCreateShadowUserAndFailsAuthentication_IfAddShadowUserOnLoginIsFalse() {
        config.setAddShadowUserOnLogin(false);
        mockToken();

        assertThatExceptionOfType(AccountNotPreCreatedException.class).isThrownBy(() -> externalOAuthAuthenticationManager.authenticate(xCodeToken));
    }

    @Test
    void rejectTokenWithInvalidSignature() {
        mockToken();

        config.setTokenKey("WRONG_KEY");

        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() -> externalOAuthAuthenticationManager.authenticate(xCodeToken));
    }

    @Test
    void rejectTokenWithInvalidSignatureAccordingToTokenKeyEndpoint() throws Exception {
        configureTokenKeyResponse("http://localhost/token_key", INVALID_RSA_SIGNING_KEY, "wrongKey");

        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() -> externalOAuthAuthenticationManager.authenticate(xCodeToken));
    }

    @Test
    void rejectTokenWithInvalidIssuer() {
        claims.put("iss", "http://wrong.issuer/");
        mockToken();

        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() -> externalOAuthAuthenticationManager.authenticate(xCodeToken));
    }

    @Test
    void rejectExpiredToken() {
        claims.put("exp", Instant.now().getEpochSecond() - 1);
        mockToken();

        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() -> externalOAuthAuthenticationManager.authenticate(xCodeToken));
    }

    @Test
    void rejectWrongAudience() {
        claims.put("aud", Arrays.asList("another_client", "a_complete_stranger"));
        mockToken();

        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() -> externalOAuthAuthenticationManager.authenticate(xCodeToken));
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
        assertThat(userArgumentCaptor.getAllValues()).hasSize(2);
        ExternalGroupAuthorizationEvent event = (ExternalGroupAuthorizationEvent) userArgumentCaptor.getAllValues().getFirst();

        UaaUser uaaUser = event.getUser();
        assertThat(uaaUser.getGivenName()).isEqualTo("Marissa");
        assertThat(uaaUser.getFamilyName()).isEqualTo("Bloggs");
        assertThat(uaaUser.getEmail()).isEqualTo("marissa@bloggs.com");
        assertThat(uaaUser.getOrigin()).isEqualTo("the_origin");
        assertThat(uaaUser.getPhoneNumber()).isEqualTo("1234567890");
        assertThat(uaaUser.getUsername()).isEqualTo("12345");
        assertThat(uaaUser.getZoneId()).isEqualTo(OriginKeys.UAA);
    }

    @Test
    void publishExternalGroupAuthorizationEvent_skippedIf_notIsRegisteredIdpAuthentication() {
        claims.put("user_name", "12345");
        claims.put("origin", "the_origin");
        claims.put("iss", UAA_ISSUER_URL);

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

        CompositeToken token = getCompositeAccessToken();
        String idToken = token.getIdTokenValue();
        xCodeToken = new ExternalOAuthCodeToken(null, null, null, idToken, null, null);

        externalOAuthAuthenticationManager.authenticate(xCodeToken);

        ArgumentCaptor<ApplicationEvent> userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(publisher, times(1)).publishEvent(userArgumentCaptor.capture());
        assertThat(userArgumentCaptor.getAllValues())
                .hasSize(1)
                .first()
                .isInstanceOf(IdentityProviderAuthenticationSuccessEvent.class);
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
        assertThat(userArgumentCaptor.getAllValues()).hasSize(3);
        assertThat(userArgumentCaptor.getAllValues().getFirst()).isInstanceOf(InvitedUserAuthenticatedEvent.class);

        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void loginAndValidateSignatureUsingTokenKeyEndpoint() throws Exception {
        config.setTokenKeyUrl(URI.create("http://localhost/token_key").toURL());
        config.setTokenKey(null);

        KeyInfo key = KeyInfoBuilder.build("correctKey", PRIVATE_KEY, UAA_ISSUER_URL);
        VerificationKeyResponse verificationKeyResponse = TokenKeyEndpoint.getVerificationKeyResponse(key);
        String response = JsonUtils.writeValueAsString(verificationKeyResponse);

        mockToken();
        mockUaaServer.expect(requestTo("http://localhost/token_key"))
                .andExpect(header("Authorization", "Basic " + new String(Base64.encodeBase64("identity:identitysecret".getBytes()))))
                .andExpect(header("Accept", "application/json,application/jwk-set+json"))
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
        assertThat(uaaUser.getUsername()).isEqualTo("marissa");
    }

    @Test
    void username_defaults_to_subject() {
        claims.remove("preferred_username");
        mockToken();
        UaaUser uaaUser = externalOAuthAuthenticationManager.getUser(xCodeToken, externalOAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken));
        assertThat(uaaUser.getUsername()).isEqualTo("12345");
    }

    @Test
    void missing_user_name_throws_auth_exception() {
        claims.remove("preferred_username");
        claims.remove("sub");
        mockToken();

        assertThatThrownBy(() -> externalOAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken))
                .isInstanceOf(InsufficientAuthenticationException.class)
                .hasMessage("Unable to map claim to a username");
    }

    @Test
    void getUserWithNullEmail() {
        claims.put("email", null);
        mockToken();
        UaaUser user = externalOAuthAuthenticationManager.getUser(xCodeToken, externalOAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken));

        assertThat(user.getEmail()).isEqualTo("12345@user.from.the_origin.cf");
    }

    @Test
    void getUserSetsTheRightOrigin() {
        externalOAuthAuthenticationManager.getUser(xCodeToken, externalOAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken));
        assertThat(externalOAuthAuthenticationManager.getOrigin()).isEqualTo(ORIGIN);

        ExternalOAuthCodeToken otherToken = new ExternalOAuthCodeToken(CODE, "other_origin", "http://localhost/callback/the_origin");
        externalOAuthAuthenticationManager.getUser(otherToken, externalOAuthAuthenticationManager.getExternalAuthenticationDetails(otherToken));
        assertThat(externalOAuthAuthenticationManager.getOrigin()).isEqualTo("other_origin");
    }

    @Test
    void getUserIssuerOverrideNotUsed() {
        mockToken();
        assertThat(externalOAuthAuthenticationManager.getUser(xCodeToken, externalOAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken))).isNotNull();
    }

    @Test
    void getUserIssuerOverrideUsedNoMatch() {
        config.setIssuer(ISSUER);
        mockToken();

        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() -> externalOAuthAuthenticationManager.getUser(
                xCodeToken,
                externalOAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken)
        ));
    }

    @Test
    void getUserIssuerOverrideUsedMatch() {
        config.setIssuer(ISSUER);
        claims.remove("iss");
        claims.put("iss", ISSUER);
        mockToken();
        assertThat(externalOAuthAuthenticationManager.getUser(xCodeToken, externalOAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken))).isNotNull();
    }

    @Test
    void authentication_context_transfers_to_authentication() {
        addTheUserOnAuth();
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication) externalOAuthAuthenticationManager.authenticate(xCodeToken);
        assertThat(authentication).isNotNull();
        assertThat(authentication.getAuthContextClassRef())
                .contains("urn:oasis:names:tc:SAML:2.0:ac:classes:Password");
    }

    @Test
    void authentication_context_when_missing() {
        addTheUserOnAuth();
        claims.remove(ClaimConstants.ACR);
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication) externalOAuthAuthenticationManager.authenticate(xCodeToken);
        assertThat(authentication).isNotNull();
        assertThat(authentication.getAuthContextClassRef()).isNull();
    }

    @Test
    void unableToAuthenticate_whenProviderIsNotOIDCOrOAuth() {
        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(MultitenancyFixture.identityProvider("the_origin", "uaa"));
        Authentication authentication = externalOAuthAuthenticationManager.authenticate(xCodeToken);
        assertThat(authentication).isNull();
    }

    @Test
    void unableToAuthenticate_whenProviderIsNotFound() {
        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(null);
        Authentication authentication = externalOAuthAuthenticationManager.authenticate(xCodeToken);
        assertThat(authentication).isNull();
    }

    @Test
    void tokenCannotBeFetchedFromCodeBecauseOfServerError() {
        IdentityProvider<OIDCIdentityProviderDefinition> identityProvider = getProvider();

        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        mockUaaServer.expect(requestTo("http://localhost/oauth/token")).andRespond(withServerError());
        assertThatExceptionOfType(HttpServerErrorException.class).isThrownBy(() -> externalOAuthAuthenticationManager.authenticate(xCodeToken));
    }

    @Test
    void tokenCannotBeFetchedFromInvalidCode() {
        IdentityProvider<OIDCIdentityProviderDefinition> identityProvider = getProvider();

        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        mockUaaServer.expect(requestTo("http://localhost/oauth/token")).andRespond(withBadRequest());
        assertThatExceptionOfType(HttpClientErrorException.class).isThrownBy(() -> externalOAuthAuthenticationManager.authenticate(xCodeToken));
    }

    @Test
    void authenticationContainsAMRClaim_fromExternalOIDCProvider() {
        addTheUserOnAuth();
        claims.put("amr", Arrays.asList("mfa", "rba"));
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication) externalOAuthAuthenticationManager.authenticate(xCodeToken);
        assertThat(authentication.getAuthenticationMethods()).contains("mfa", "rba", "ext", "oauth");
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
        assertThat(actualUaaUser.getEmail()).isEqualTo("test@email.org");
        assertThat(actualUaaUser.getGivenName()).isEqualTo("first_name");
        assertThat(actualUaaUser.getFamilyName()).isEqualTo("last_name");
        assertThat(actualUaaUser.getPhoneNumber()).isEqualTo("randomNumber");
        assertThat(actualUaaUser.isVerified()).as("verified").isTrue();
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
        assertThat(actualUaaUser.isVerified()).as("verified").isFalse();
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
        assertThat(actualUaaUser.isVerified()).as("verified").isTrue();
    }

    @Test
    void email_verified_mapping_is_not_there() {
        addTheUserOnAuth();
        attributeMappings.remove("email_verified");
        config.setStoreCustomAttributes(true);
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication) externalOAuthAuthenticationManager.authenticate(xCodeToken);
        UaaUser actualUaaUser = externalOAuthAuthenticationManager.getUserDatabase().retrieveUserById(authentication.getPrincipal().getId());
        assertThat(actualUaaUser.isVerified()).as("verified").isTrue();
    }

    @Test
    void email_verified_is_omitted() {
        addTheUserOnAuth();
        claims.remove("email_verified");
        attributeMappings.put("email_verified", "email_verified");
        config.setStoreCustomAttributes(true);
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication) externalOAuthAuthenticationManager.authenticate(xCodeToken);
        UaaUser actualUaaUser = externalOAuthAuthenticationManager.getUserDatabase().retrieveUserById(authentication.getPrincipal().getId());
        assertThat(actualUaaUser.isVerified()).as("verified").isFalse();
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

        assertThat(authentication.getUserAttributes()).isEqualTo(map);
        assertThat(authentication.getExternalGroups()).containsAll(scopes);
        UserInfo info = new UserInfo()
                .setUserAttributes(map)
                .setRoles(scopes);
        UserInfo actualUserInfo = externalOAuthAuthenticationManager.getUserDatabase().getUserInfo(authentication.getPrincipal().getId());
        assertThat(info.getUserAttributes()).isEqualTo(actualUserInfo.getUserAttributes());
        assertThat(actualUserInfo.getRoles()).containsAll(info.getRoles());

        UaaUser actualUser = externalOAuthAuthenticationManager.getUserDatabase().retrieveUserByName("12345", "the_origin");
        assertThat(actualUser).isNotNull();
        assertThat(actualUser.getGivenName()).isEqualTo("Marissa");
    }

    private void assertUserCreated(NewUserAuthenticatedEvent event) {
        assertThat(event).isNotNull();
        UaaUser uaaUser = event.getUser();
        assertThat(uaaUser).isNotNull();
        assertThat(uaaUser.getGivenName()).isEqualTo("Marissa");
        assertThat(uaaUser.getFamilyName()).isEqualTo("Bloggs");
        assertThat(uaaUser.getEmail()).isEqualTo("marissa@bloggs.com");
        assertThat(uaaUser.getOrigin()).isEqualTo("the_origin");
        assertThat(uaaUser.getPhoneNumber()).isEqualTo("1234567890");
        assertThat(uaaUser.getUsername()).isEqualTo("12345");
        assertThat(uaaUser.getZoneId()).isEqualTo(OriginKeys.UAA);
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
                .andExpect(header("Accept", "application/json,application/jwk-set+json"))
                .andRespond(withStatus(OK).contentType(APPLICATION_JSON).body(response));
    }

    private void addTheUserOnAuth() {
        doAnswer(invocation -> {
            Object e = invocation.getArguments()[0];
            if (e instanceof NewUserAuthenticatedEvent event) {
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
                .andExpect(content().string(containsString("response_type=id_token")))
                .andRespond(withStatus(OK).contentType(APPLICATION_JSON).body(response));
    }

    private CompositeToken getCompositeAccessToken() {
        return getCompositeAccessToken(emptyList());
    }

    private CompositeToken getCompositeAccessToken(List<String> removeClaims) {
        removeClaims.stream().forEach(c -> claims.remove(c));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);

        IdentityProvider<OIDCIdentityProviderDefinition> identityProvider = getProvider();
        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        CompositeToken compositeToken = new CompositeToken("accessToken");
        compositeToken.setIdTokenValue(idTokenJwt);
        return compositeToken;
    }

    private String getIdTokenResponse() {
        return JsonUtils.writeValueAsString(getCompositeAccessToken());
    }

    private IdentityProvider<OIDCIdentityProviderDefinition> getProvider() {
        IdentityProvider<OIDCIdentityProviderDefinition> identityProvider = new IdentityProvider<>();
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

        List<String> authorities = uaaUser.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
        for (String scope : SCOPES_LIST) {
            assertThat(authorities).contains(scope);
        }
    }

    private static Stream<String> invalidOrigins() {
        return Stream.of("", null);
    }
}
