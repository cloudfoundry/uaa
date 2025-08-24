package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.cloudfoundry.identity.uaa.client.ClientJwtConfiguration;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.beans.ApplicationContextProvider;
import org.cloudfoundry.identity.uaa.oauth.client.ClientJwtCredential;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeyHelper;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthAuthenticationManager;
import org.cloudfoundry.identity.uaa.provider.oauth.OidcMetadataFetcher;
import org.cloudfoundry.identity.uaa.provider.oauth.OidcMetadataFetchingException;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.net.MalformedURLException;
import java.net.URI;
import java.text.ParseException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtClientAuthenticationTest {

    private static final String KEY_ID = "tokenKeyId";
    private static final String INVALID_CLIENT_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJjYmEyZmRlN2ZkYTg0YzMzYTdkZDQ5MWVmMzljZWY5NiIsImF1ZCI6WyJodHRwOi8vbG9jYWxob3N0OjgwODAvdWFhL29hdXRoL3Rva2VuIl0sInN1YiI6ImlkZW50aXR5IiwiaXNzIjoic29tZVRoaW5nIn0.HLXpsPJw0SvF8DcGmmifzJJLxX4hmfwILAtAFedk48c";
    private static final String INVALID_CLIENT_ALG = "eyJhbGciOiJIUzI1NiIsImtpZCI6InRva2VuS2V5SWQiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE2OTU4NDEyMDYsImp0aSI6ImRhMzdjYzFjMjkzOTQzMWE4YjUzZTI5MmZiMjYxMDZhIiwiYXVkIjpbImh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC91YWEvb2F1dGgvdG9rZW4iXSwic3ViIjoiaWRlbnRpdHkiLCJpc3MiOiJpZGVudGl0eSIsImlhdCI6MTY5NTg0MDc4NiwicmV2b2NhYmxlIjpmYWxzZX0.gFYuUjzupzeKNK2Uq3Ijp0rDIcJfI80wl3Pt5MSypPM";

    private OIDCIdentityProviderDefinition config;
    private final KeyInfoService keyInfoService = mock(KeyInfoService.class);
    private final OidcMetadataFetcher oidcMetadataFetcher = mock(OidcMetadataFetcher.class);
    private final ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager = mock(ExternalOAuthAuthenticationManager.class);
    private final String issuer = "http://localhost:8080/uaa/oauth/token";
    private JwtClientAuthentication jwtClientAuthentication;

    @BeforeEach
    void setup() throws MalformedURLException, JOSEException {
        IdentityZoneHolder.set(IdentityZone.getUaa());
        jwtClientAuthentication = new JwtClientAuthentication(keyInfoService);
        mockOIDCDefinition(null);
        mockKeyInfoService(null, null);
        mockApplicationContext(Map.of());
    }

    @AfterEach
    void cleanup() {
        IdentityZoneHolder.clear();
    }

    @Test
    void getClientAssertion() throws ParseException {
        // When
        String clientAssertion = jwtClientAuthentication.getClientAssertion(config);
        // Then
        validateClientAssertionOidcCompliant(clientAssertion);
    }

    @Test
    void getClientAssertionUsingTrueBooleanConfig() throws ParseException {
        // Given
        config.setJwtClientAuthentication(true);
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        // When
        params = jwtClientAuthentication.getClientAuthenticationParameters(params, config);
        // Then
        assertThat(params).containsKey("client_assertion")
                .containsKey("client_assertion_type");
        String clientAssertion = params.get("client_assertion").getFirst();
        validateClientAssertionOidcCompliant(clientAssertion);
        JWSHeader header = getJwtHeader(clientAssertion);
        assertThat(header.getKeyID()).isEqualTo(KEY_ID);
    }

    @Test
    void getClientAssertionUsingFalseBooleanConfig() {
        // Given
        config.setJwtClientAuthentication(false);
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        // When
        params = jwtClientAuthentication.getClientAuthenticationParameters(params, config);
        // Then
        assertThat(params).doesNotContainKey("client_assertion")
                .doesNotContainKey("client_assertion_type");
    }

    @Test
    void getClientAssertionUsingCustomConfig() throws ParseException {
        // Given
        Map<Object, Object> customClaims = Map.of("iss", "identity");
        config.setJwtClientAuthentication(customClaims);
        // When
        String clientAssertion = jwtClientAuthentication.getClientAssertion(config);
        // Then
        validateClientAssertionOidcCompliant(clientAssertion);
    }

    @Test
    void getClientAssertionRfc7523Compliant() throws ParseException {
        // Given
        Map<Object, Object> customClaims = new HashMap<>();
        customClaims.put("iss", "anotherIssuer");
        customClaims.put("aud", "ReceiverEndpoint");
        config.setJwtClientAuthentication(customClaims);
        // When
        String clientAssertion = jwtClientAuthentication.getClientAssertion(config);
        // Then
        validateClientAssertionRfc7523Compliant(clientAssertion, "anotherIssuer", "ReceiverEndpoint");
    }

    @Test
    void getClientAuthenticationParameters() throws ParseException {
        // Given
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        // When
        params = jwtClientAuthentication.getClientAuthenticationParameters(params, config);
        // Then
        assertThat(params).containsKey("client_assertion")
                .containsKey("client_assertion_type")
                .containsEntry("client_assertion_type", Collections.singletonList(JwtClientAuthentication.GRANT_TYPE));
        assertThat(params.get("client_assertion").getFirst()).isNotNull();
        validateClientAssertionOidcCompliant(params.get("client_assertion").getFirst());
    }

    @Test
    void getClientAuthenticationParametersNullParameter() {
        // When
        assertThat(jwtClientAuthentication.getClientAuthenticationParameters(null, null)).isNull();
    }

    @Test
    void getClientAuthenticationParametersNullJwtClientConfiguration() {
        // Given
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        config.setJwtClientAuthentication(null);
        // When
        assertThat(jwtClientAuthentication.getClientAuthenticationParameters(params, config)).isEqualTo(params);
    }

    @Test
    void getClientAssertionUnknownSingingKey() {
        // Given
        Map<Object, Object> customClaims = new HashMap<>();
        customClaims.put("kid", "wrong-key-id");
        config.setJwtClientAuthentication(customClaims);

        assertThatThrownBy(() -> jwtClientAuthentication.getClientAssertion(config))
                .isExactlyInstanceOf(BadCredentialsException.class);
    }

    @Test
    void getClientAssertionUsingCustomSingingKeyFromEnvironment() throws ParseException, JOSEException {
        // Given: register 2 keys
        mockKeyInfoService("key-id-321", JwtHelperX5tTest.CERTIFICATE_1);
        Map<Object, Object> customClaims = new HashMap<>();
        // reference to customer one key-id-321 and set default
        customClaims.put("kid", "${jwt.client.kid:" + KEY_ID + "}");
        config.setJwtClientAuthentication(customClaims);
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        Map<String, Object> keyMap = Map.of("jwt.client.kid", "key-id-321");
        mockApplicationContext(keyMap);
        // When
        params = jwtClientAuthentication.getClientAuthenticationParameters(params, config);
        // Then
        assertThat(params).containsKey("client_assertion")
                .containsKey("client_assertion_type");
        String clientAssertion = params.get("client_assertion").getFirst();
        validateClientAssertionOidcCompliant(clientAssertion);
        JWSHeader header = getJwtHeader(clientAssertion);
        assertThat(header.getKeyID()).isEqualTo("key-id-321");
        assertThat(header.getJWKURL()).isNull();
    }

    @Test
    void getClientAssertionUsingCustomSingingKeyFromEnvironmentNoDefault() throws ParseException, JOSEException {
        // Given: register 2 keys
        mockKeyInfoService("key-id-321", JwtHelperX5tTest.CERTIFICATE_1);
        Map<Object, Object> customClaims = new HashMap<>();
        // reference to customer one key-id-321
        customClaims.put("kid", "${jwt.client.kid}");
        config.setJwtClientAuthentication(customClaims);
        mockApplicationContext(Map.of("jwt.client.kid", "key-id-321"));
        // When
        MultiValueMap<String, String> params = jwtClientAuthentication.getClientAuthenticationParameters(new LinkedMultiValueMap<>(), config);
        // Then
        assertThat(params).containsKey("client_assertion")
                .containsKey("client_assertion_type");
        String clientAssertion = params.get("client_assertion").getFirst();
        validateClientAssertionOidcCompliant(clientAssertion);
        JWSHeader header = getJwtHeader(clientAssertion);
        assertThat(header.getKeyID()).isEqualTo("key-id-321");
        assertThat(header.getJWKURL()).isNull();
    }

    @Test
    void getClientAssertionUsingCustomSingingKeyFromEnvironmentButEntryIsMissing() throws JOSEException {
        // Given: register 2 keys
        mockKeyInfoService("key-id-321", JwtHelperX5tTest.CERTIFICATE_1);
        Map<Object, Object> customClaims = new HashMap<>();
        // reference in jwtClientAuthentication to a customer key, but this does not exist, then use default KEY_ID
        customClaims.put("kid", "${jwt.client.kid:" + KEY_ID + "}");
        config.setJwtClientAuthentication(customClaims);
        // empty application context
        mockApplicationContext(Map.of());
        // Then
        LinkedMultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        assertThatThrownBy(() -> jwtClientAuthentication.getClientAuthenticationParameters(params, config))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Missing referenced signing entry");
    }

    @Test
    void getClientAssertionUsingCustomSingingKeyFromEnvironmentButNotInDefaultZone() throws JOSEException {
        // Given: register 2 keys
        mockKeyInfoService("key-id-321", JwtHelperX5tTest.CERTIFICATE_1);
        Map<Object, Object> customClaims = new HashMap<>();
        // reference in jwtClientAuthentication to a custom key, but call it not from UAA zone
        customClaims.put("kid", "${jwt.client.kid}");
        config.setJwtClientAuthentication(customClaims);
        mockApplicationContext(Map.of("jwt.client.kid", "key-id-321"));
        IdentityZone currentZone = IdentityZone.getUaa();
        // modify to custom zone
        currentZone.setId(new AlphanumericRandomValueStringGenerator().generate());
        currentZone.setSubdomain(new AlphanumericRandomValueStringGenerator().generate());
        IdentityZoneHolder.set(currentZone);
        // Expect
        LinkedMultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        assertThatThrownBy(() -> jwtClientAuthentication.getClientAuthenticationParameters(params, config))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Missing requested signing key");
    }

    @Test
    void getClientAssertionCustomSingingKeyButNoCertificate() throws ParseException, JOSEException {
        // Given
        mockKeyInfoService("myKey", null);
        Map<Object, Object> customClaims = new HashMap<>();
        customClaims.put("kid", "myKey");
        config.setJwtClientAuthentication(customClaims);
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        // When
        params = jwtClientAuthentication.getClientAuthenticationParameters(params, config);
        // Then
        assertThat(params).containsKey("client_assertion")
                .containsKey("client_assertion_type");
        String clientAssertion = params.get("client_assertion").getFirst();
        validateClientAssertionOidcCompliant(clientAssertion);
        JWSHeader header = getJwtHeader(clientAssertion);
        assertThat(header.getKeyID()).isEqualTo("myKey");
        assertThat(header.getJWKURL()).hasToString("http://localhost:8080/uaa/token_key");
    }

    @Test
    void getClientAssertionUsingCustomSingingPrivateKeyFromEnvironment() throws ParseException, JOSEException {
        // Given: register 2 keys
        mockKeyInfoService("key-id-321", JwtHelperX5tTest.CERTIFICATE_1);
        // add reference in jwtClientAuthentication to customer one key-id-321
        Map<Object, Object> customClaims = new HashMap<>();
        customClaims.put("kid", "${jwt.client.kid}");
        customClaims.put("key", "${jwt.client.key}");
        customClaims.put("cert", "${jwt.client.cert}");
        config.setJwtClientAuthentication(customClaims);
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        Map<String, Object> keyMap = Map.of("jwt.client.kid", "key-id-321",
                "jwt.client.key", JwtHelperX5tTest.SIGNING_KEY_1,
                "jwt.client.cert", JwtHelperX5tTest.CERTIFICATE_1);
        mockApplicationContext(keyMap);
        // When
        params = jwtClientAuthentication.getClientAuthenticationParameters(params, config);
        // Then
        assertThat(params).containsKey("client_assertion")
                .containsKey("client_assertion_type");
        String clientAssertion = params.get("client_assertion").getFirst();
        validateClientAssertionOidcCompliant(clientAssertion);
        JWSHeader header = getJwtHeader(clientAssertion);
        assertThat(header.getKeyID()).isEqualTo("key-id-321");
        assertThat(header.getJWKURL()).isNull();
    }

    @Test
    void getClientAssertionUsingCustomSingingPrivateKeyFromEnvironmentDisabledForCustomZone() throws JOSEException {
        arrangeCustomIdz();

        // Given: register 2 keys
        mockKeyInfoService("key-id-321", JwtHelperX5tTest.CERTIFICATE_1);

        // add reference in jwtClientAuthentication to customer one key-id-321
        Map<Object, Object> customClaims = new HashMap<>();
        customClaims.put("kid", "${jwt.client.kid}");
        customClaims.put("key", "${jwt.client.key}");
        customClaims.put("cert", "${jwt.client.cert}");
        config.setJwtClientAuthentication(customClaims);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        final Map<String, Object> keyMap = Map.of(
                "jwt.client.kid", "key-id-321",
                "jwt.client.key", JwtHelperX5tTest.SIGNING_KEY_1,
                "jwt.client.cert", JwtHelperX5tTest.CERTIFICATE_1
        );
        mockApplicationContext(keyMap);

        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() ->
                jwtClientAuthentication.getClientAuthenticationParameters(params, config, false)
        ).withMessage("Missing requested signing key");
    }

    @Test
    void getClientAssertionUsingCustomSingingPrivateKeyFromEnvironmentEnabledForCustomZone() throws ParseException, JOSEException {
        arrangeCustomIdz();

        // Given: register 2 keys
        mockKeyInfoService("key-id-321", JwtHelperX5tTest.CERTIFICATE_1);

        // add reference in jwtClientAuthentication to customer one key-id-321
        Map<Object, Object> customClaims = new HashMap<>();
        customClaims.put("kid", "${jwt.client.kid}");
        customClaims.put("key", "${jwt.client.key}");
        customClaims.put("cert", "${jwt.client.cert}");
        config.setJwtClientAuthentication(customClaims);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        final Map<String, Object> keyMap = Map.of(
                "jwt.client.kid", "key-id-321",
                "jwt.client.key", JwtHelperX5tTest.SIGNING_KEY_1,
                "jwt.client.cert", JwtHelperX5tTest.CERTIFICATE_1
        );
        mockApplicationContext(keyMap);

        // When
        params = jwtClientAuthentication.getClientAuthenticationParameters(params, config, true);

        // Then
        assertThat(params).containsKey("client_assertion")
                .containsKey("client_assertion_type");
        final String clientAssertion = params.get("client_assertion").getFirst();
        validateClientAssertionOidcCompliant(clientAssertion);
        final JWSHeader header = getJwtHeader(clientAssertion);
        assertThat(header.getKeyID()).isEqualTo("key-id-321");
        assertThat(header.getJWKURL()).isNull();
    }

    private static void arrangeCustomIdz() {
        final IdentityZone customZone = new IdentityZone();
        customZone.setId(new AlphanumericRandomValueStringGenerator(8).generate().toLowerCase());
        new IdentityZoneManagerImpl().setCurrentIdentityZone(customZone);
    }

    @Test
    void getClientIdOfClientAssertionOidcAssertion() {
        // When
        String clientAssertion = jwtClientAuthentication.getClientAssertion(config);
        // Then
        assertThat(JwtClientAuthentication.getClientIdOidcAssertion(clientAssertion)).isEqualTo("identity");
    }

    @Test
    void requestInvalidateClientAssertion() throws Exception {
        // Then
        assertThat(jwtClientAuthentication.validateClientJwt(getMockedRequestParameter("test", INVALID_CLIENT_JWT), getMockedClientJwtConfiguration(), "identity")).isFalse();
    }

    @Test
    void wrongAssertionInvalidateClientId() {
        // Given
        jwtClientAuthentication = new JwtClientAuthentication(keyInfoService, oidcMetadataFetcher, externalOAuthAuthenticationManager);
        // Then
        assertThatThrownBy(() -> jwtClientAuthentication.validateClientJwt(getMockedRequestParameter(null, jwtClientAuthentication.getClientAssertion(config)),
                // pass a different client_id to the provided one from client_assertion JWT
                getMockedClientJwtConfiguration(), "wrong_client_id"))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Wrong client_assertion");
    }

    @Test
    void badAlgorithmInvalidateClientId() throws Exception {
        // Given
        jwtClientAuthentication = new JwtClientAuthentication(keyInfoService, oidcMetadataFetcher, externalOAuthAuthenticationManager);
        ClientJwtConfiguration clientJwtConfiguration = getMockedClientJwtConfiguration();
        when(oidcMetadataFetcher.fetchWebKeySet(clientJwtConfiguration)).thenReturn(clientJwtConfiguration.getJwkSet());
        // Then
        assertThatThrownBy(() -> jwtClientAuthentication.validateClientJwt(getMockedRequestParameter(null, INVALID_CLIENT_ALG),
                clientJwtConfiguration, "identity"))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Bad client_assertion algorithm");
    }

    @Test
    void oidcFetchFailed() throws Exception {
        // Given
        jwtClientAuthentication = new JwtClientAuthentication(keyInfoService, oidcMetadataFetcher, externalOAuthAuthenticationManager);
        ClientJwtConfiguration clientJwtConfiguration = getMockedClientJwtConfiguration();
        when(oidcMetadataFetcher.fetchWebKeySet(clientJwtConfiguration)).thenThrow(new OidcMetadataFetchingException(""));
        // Then
        assertThatThrownBy(() -> jwtClientAuthentication.validateClientJwt(getMockedRequestParameter(null, jwtClientAuthentication.getClientAssertion(config)),
                clientJwtConfiguration, "identity"))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Bad client_assertion");
    }

    @Test
    void oidcFetchEmptyKeys() throws Exception {
        // Given
        jwtClientAuthentication = new JwtClientAuthentication(keyInfoService, null, externalOAuthAuthenticationManager);
        ClientJwtConfiguration clientJwtConfiguration = getMockedClientJwtConfiguration();
        // Then
        assertThatThrownBy(() -> jwtClientAuthentication.validateClientJwt(getMockedRequestParameter(null, jwtClientAuthentication.getClientAssertion(config)),
                clientJwtConfiguration, "identity"))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Bad empty jwk_set");
    }

    @Test
    void untrustedClientAssertion() throws Exception {
        // Given
        jwtClientAuthentication = new JwtClientAuthentication(keyInfoService, oidcMetadataFetcher, externalOAuthAuthenticationManager);
        // create client assertion with key ids which won't map to provide JWT,
        // lead to failing validateClientJWToken check
        ClientJwtConfiguration clientJwtConfiguration = getMockedClientJwtConfiguration("extId");
        when(oidcMetadataFetcher.fetchWebKeySet(clientJwtConfiguration)).thenReturn(clientJwtConfiguration.getJwkSet());
        String clientAssertion = jwtClientAuthentication.getClientAssertion(config);
        // When
        assertThatThrownBy(() -> jwtClientAuthentication.validateClientJwt(getMockedRequestParameter(null, clientAssertion), clientJwtConfiguration, "identity"))
                // Then, expect key resolution error because of not matching configured keys to JWT kid
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Untrusted client_assertion");
    }

    @Test
    void signatureInvalidateClientAssertion() throws Exception {
        // Given
        jwtClientAuthentication = new JwtClientAuthentication(keyInfoService, oidcMetadataFetcher, externalOAuthAuthenticationManager);
        ClientJwtConfiguration clientJwtConfiguration = getMockedClientJwtConfiguration();
        when(oidcMetadataFetcher.fetchWebKeySet(clientJwtConfiguration)).thenReturn(clientJwtConfiguration.getJwkSet());
        String clientAssertion = jwtClientAuthentication.getClientAssertion(config);
        // When
        assertThatThrownBy(() -> jwtClientAuthentication.validateClientJwt(getMockedRequestParameter(null, clientAssertion), clientJwtConfiguration, "identity"))
                // Then, expect signature failed because mockKeyInfoService creates a corrupted signature
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Unauthorized client_assertion");
    }

    @Test
    void getClientIdOfInvalidClientAssertionOidcCompliance() {
        // Then
        assertThat(JwtClientAuthentication.getClientIdOidcAssertion(INVALID_CLIENT_JWT)).isNull();
        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> JwtClientAuthentication.getClientIdOidcAssertion("eyXXX"));
    }

    @Test
    void clientJwtFederatedCreateAndValidateOwnAssertion() throws MalformedURLException, JOSEException {
        // Given
        jwtClientAuthentication = new JwtClientAuthentication(keyInfoService, oidcMetadataFetcher, externalOAuthAuthenticationManager);
        mockKeyInfoService(KEY_ID, JwtHelperX5tTest.CERTIFICATE_1, JwtHelperX5tTest.SIGNING_KEY_1);
        ClientJwtCredential clientJwtCredential = new ClientJwtCredential("subject", issuer, "audience");
        mockOIDCDefinition(clientJwtCredential);
        String clientAssertion = jwtClientAuthentication.getClientAssertion(config);
        when(externalOAuthAuthenticationManager.idTokenWasIssuedByTheUaa(issuer)).thenReturn(true);
        // Then
        assertThat(jwtClientAuthentication.validateClientJwt(getMockedRequestParameter(null, clientAssertion),
                getMockedClientJwtConfiguration(clientJwtCredential), "own_client_id")).isTrue();
    }

    @Test
    void clientJwtFederatedCreateAndValidateTrustedIssuer() throws MalformedURLException, JOSEException, ParseException {
        // Given
        jwtClientAuthentication = new JwtClientAuthentication(keyInfoService, oidcMetadataFetcher, externalOAuthAuthenticationManager);
        mockKeyInfoService(KEY_ID, JwtHelperX5tTest.CERTIFICATE_1, JwtHelperX5tTest.SIGNING_KEY_1);
        ClientJwtCredential clientJwtCredential = new ClientJwtCredential("subject", "http://external-issuer", "audience");
        mockOIDCDefinition(clientJwtCredential);
        String clientAssertion = jwtClientAuthentication.getClientAssertion(config);
        when(externalOAuthAuthenticationManager.idTokenWasIssuedByTheUaa("http://external-issuer")).thenReturn(false);
        when(externalOAuthAuthenticationManager.retrieveRegisteredIdentityProviderByIssuer("http://external-issuer")).thenThrow(new IncorrectResultSizeDataAccessException(0));
        when(externalOAuthAuthenticationManager.getTokenKeyFromOAuth(any())).thenReturn(JsonWebKeyHelper.deserialize(new JWKSet(JWK.parse(mockJWKMap(KEY_ID, JwtHelperX5tTest.SIGNING_KEY_1))).toString()));
        // Then
        assertThat(jwtClientAuthentication.validateClientJwt(getMockedRequestParameter(null, clientAssertion),
                getMockedClientJwtConfiguration(clientJwtCredential), "extern_client_id")).isTrue();
    }

    @Test
    void clientJwtFederatedCreateAndValidateTrustedIdP() throws MalformedURLException, JOSEException, ParseException {
        // Given
        IdentityProvider idp = new IdentityProvider();
        OIDCIdentityProviderDefinition idpConfig = new OIDCIdentityProviderDefinition();
        idp.setConfig(idpConfig);
        jwtClientAuthentication = new JwtClientAuthentication(keyInfoService, oidcMetadataFetcher, externalOAuthAuthenticationManager);
        mockKeyInfoService(KEY_ID, JwtHelperX5tTest.CERTIFICATE_1, JwtHelperX5tTest.SIGNING_KEY_1);
        ClientJwtCredential clientJwtCredential = new ClientJwtCredential("subject", "http://external-issuer", "audience");
        mockOIDCDefinition(clientJwtCredential);
        String clientAssertion = jwtClientAuthentication.getClientAssertion(config);
        when(externalOAuthAuthenticationManager.idTokenWasIssuedByTheUaa("http://external-issuer")).thenReturn(false);
        when(externalOAuthAuthenticationManager.retrieveRegisteredIdentityProviderByIssuer("http://external-issuer")).thenReturn(idp);
        when(externalOAuthAuthenticationManager.getTokenKeyFromOAuth(idpConfig)).thenReturn(JsonWebKeyHelper.deserialize(new JWKSet(JWK.parse(mockJWKMap(KEY_ID, JwtHelperX5tTest.SIGNING_KEY_1))).toString()));
        // Then
        assertThat(jwtClientAuthentication.validateClientJwt(getMockedRequestParameter(null, clientAssertion),
                getMockedClientJwtConfiguration(clientJwtCredential), "extern_client_id")).isTrue();
    }

    @Test
    void clientJwtFederatedCreateAndValidateWrongIdPAndWrongIssuer() throws MalformedURLException, JOSEException, ParseException {
        // Given
        IdentityProvider idp = new IdentityProvider();
        SamlIdentityProviderDefinition idpConfig = new SamlIdentityProviderDefinition();
        idp.setConfig(idpConfig);
        jwtClientAuthentication = new JwtClientAuthentication(keyInfoService, oidcMetadataFetcher, externalOAuthAuthenticationManager);
        mockKeyInfoService(KEY_ID, JwtHelperX5tTest.CERTIFICATE_1, JwtHelperX5tTest.SIGNING_KEY_1);
        ClientJwtCredential clientJwtCredential = new ClientJwtCredential("subject", "external-issuer", "audience");
        mockOIDCDefinition(clientJwtCredential);
        String clientAssertion = jwtClientAuthentication.getClientAssertion(config);
        when(externalOAuthAuthenticationManager.idTokenWasIssuedByTheUaa("external-issuer")).thenReturn(false);
        when(externalOAuthAuthenticationManager.retrieveRegisteredIdentityProviderByIssuer("external-issuer")).thenReturn(idp);
        // Then
        assertThat(
                jwtClientAuthentication.validateClientJwt(
                        getMockedRequestParameter(null, clientAssertion),
                        getMockedClientJwtConfiguration(clientJwtCredential),
                        "extern_client_id"
                )
        ).isFalse();
    }

    private void mockKeyInfoService(String keyId, String x509Certificate) throws JOSEException {
        mockKeyInfoService(keyId, x509Certificate, null);
    }

    private void mockKeyInfoService(String keyId, String x509Certificate, String privateKey) throws JOSEException {
        KeyInfo keyInfo = mock(KeyInfo.class);
        String keyInfoKid = keyId != null ? keyId : KEY_ID;
        JWSSigner signer = mockJWSigner(keyInfoKid, privateKey);
        if (keyId != null) {
            KeyInfo customKeyInfo = mock(KeyInfo.class);
            when(customKeyInfo.keyId()).thenReturn(keyId);
            when(keyInfoService.getKey(keyId)).thenReturn(customKeyInfo);
            when(customKeyInfo.algorithm()).thenReturn("RS256");
            when(customKeyInfo.keyURL()).thenReturn("http://localhost:8080/uaa/token_key");
            when(customKeyInfo.getSigner()).thenReturn(signer);
            when(customKeyInfo.verifierCertificate()).thenReturn(x509Certificate != null ? Optional.of(X509CertUtils.parse(x509Certificate)) : Optional.empty());
        }
        when(keyInfo.keyId()).thenReturn(keyInfoKid);
        when(keyInfoService.getKey(KEY_ID)).thenReturn(keyInfo);
        when(keyInfoService.getActiveKey()).thenReturn(keyInfo);
        when(keyInfoService.getKeys()).thenReturn(Map.of(keyInfoKid, keyInfo));
        when(keyInfo.algorithm()).thenReturn("RS256");
        when(keyInfo.keyURL()).thenReturn("http://localhost:8080/uaa/token_key");
        when(keyInfo.getSigner()).thenReturn(signer);
        when(keyInfo.getJwkMap()).thenReturn(mockJWKMap(keyInfoKid, privateKey));
        when(keyInfo.verifierCertificate()).thenReturn(x509Certificate != null ? Optional.of(X509CertUtils.parse(x509Certificate)) : Optional.of(X509CertUtils.parse(JwtHelperX5tTest.CERTIFICATE_1)));

    }

    private JWSSigner mockJWSigner(String keyId, String privateKey) throws JOSEException {
        if (privateKey != null) {
            KeyInfo keyInfo = new KeyInfo(keyId, privateKey, issuer);
            return keyInfo.getSigner();
        } else {
            JWSSigner signer = mock(JWSSigner.class);
            when(signer.supportedJWSAlgorithms()).thenReturn(Set.of(JWSAlgorithm.RS256));
            when(signer.sign(any(), any())).thenReturn(new Base64URL("dummy"));
            return signer;
        }
    }

    private void mockApplicationContext(Map<String, Object> environmentMap) {
        ApplicationContext applicationContext = mock(ApplicationContext.class);
        Environment environment = mock(Environment.class);
        when(applicationContext.getEnvironment()).thenReturn(environment);
        environmentMap.keySet().forEach(e -> when(environment.getProperty(e)).thenReturn((String) environmentMap.get(e)));
        new ApplicationContextProvider().setApplicationContext(applicationContext);
    }

    private void mockOIDCDefinition(ClientJwtCredential credential) throws MalformedURLException {
        config = new OIDCIdentityProviderDefinition();
        config.setTokenUrl(URI.create("http://localhost:8080/uaa/oauth/token").toURL());
        config.setRelyingPartyId("identity");
        if (credential != null) {
            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", credential.getSubject());
            claims.put("iss", credential.getIssuer());
            if (credential.getAudience() != null) {
                claims.put("aud", credential.getAudience());
            }
            config.setJwtClientAuthentication(claims);
        } else {
            config.setJwtClientAuthentication(true);
        }
    }

    private Map<String, Object> mockJWKMap(String keyId, String privateKey) {
        if (privateKey == null) {
            return new HashMap<>();
        }
        return new KeyInfo(keyId, privateKey, issuer).getJwkMap();
    }

    private static JWSHeader getJwtHeader(String jwtString) throws ParseException {
        JWT jwt = JWTParser.parse(jwtString);
        return (JWSHeader) jwt.getHeader();
    }

    private static void validateClientAssertionOidcCompliant(String clientAssertion) throws ParseException {
        JWTClaimsSet jwtClaimsSet = JWTParser.parse(clientAssertion).getJWTClaimsSet();
        assertThat(jwtClaimsSet.getAudience()).isEqualTo(Collections.singletonList("http://localhost:8080/uaa/oauth/token"));
        assertThat(jwtClaimsSet.getSubject()).isEqualTo("identity");
        assertThat(jwtClaimsSet.getIssuer()).isEqualTo("identity");
    }

    private static void validateClientAssertionRfc7523Compliant(String clientAssertion, String iss, String aud) throws ParseException {
        JWTClaimsSet jwtClaimsSet = JWTParser.parse(clientAssertion).getJWTClaimsSet();
        assertThat(jwtClaimsSet.getAudience()).isEqualTo(Collections.singletonList(aud));
        assertThat(jwtClaimsSet.getIssuer()).isEqualTo(iss);
        assertThat(jwtClaimsSet.getSubject()).isEqualTo("identity");
    }

    private static Map<String, String[]> getMockedRequestParameter(String type, String assertion) {
        Map<String, String[]> requestParameters = new HashMap<>();
        if (type != null) {
            requestParameters.put(JwtClientAuthentication.CLIENT_ASSERTION_TYPE, new String[]{type});
        } else {
            requestParameters.put(JwtClientAuthentication.CLIENT_ASSERTION_TYPE, new String[]{JwtClientAuthentication.GRANT_TYPE});
        }
        requestParameters.put(JwtClientAuthentication.CLIENT_ASSERTION, new String[]{assertion});
        return requestParameters;
    }

    private static ClientJwtConfiguration getMockedClientJwtConfiguration() throws ParseException {
        return getMockedClientJwtConfiguration((String) null);
    }

    private static ClientJwtConfiguration getMockedClientJwtConfiguration(String keyId) throws ParseException {
        KeyInfo keyInfo = KeyInfoBuilder.build(keyId != null ? keyId : "tokenKeyId", JwtHelperX5tTest.SIGNING_KEY_1, "http://localhost:8080/uaa");
        return ClientJwtConfiguration.parse(JWK.parse(keyInfo.getJwkMap()).toString());
    }

    private static ClientJwtConfiguration getMockedClientJwtConfiguration(ClientJwtCredential credential) {
        return new ClientJwtConfiguration(List.of(credential));
    }
}
