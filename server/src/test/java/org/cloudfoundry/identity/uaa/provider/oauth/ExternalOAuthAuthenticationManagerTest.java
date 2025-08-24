package org.cloudfoundry.identity.uaa.provider.oauth;

import com.github.benmanes.caffeine.cache.Ticker;
import com.nimbusds.jose.HeaderParameterNames;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.cloudfoundry.identity.uaa.authentication.ProviderConfigurationException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaLoginHint;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.cache.StaleUrlCache;
import org.cloudfoundry.identity.uaa.client.UaaClient;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.login.Prompt;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtClientAuthentication;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelperX5tTest;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.LinkedMaskingMultiValueMap;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.net.MalformedURLException;
import java.net.URI;
import java.text.ParseException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AUD;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EMAIL;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EXPIRY_IN_SECONDS;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ISS;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ROLES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SUB;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.FAMILY_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.entry;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.map;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.DEFAULT_UAA_URL;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ExternalOAuthAuthenticationManagerTest {
    private static final String OIDC_PROVIDER_KEY = "oidc-provider-key";
    private static final String ORIGIN = "google-oidc";
    private static final String ZONE_ID = "zoneId";
    private static final String UAA_ISSUER_BASE_URL = "http://uaa.example.com";

    private static final String UAA_IDENTITY_ZONE_TOKEN_SIGNING_KEY = """
            -----BEGIN RSA PRIVATE KEY-----
            MIICXgIBAAKBgQDR94jLH/fHUjdMzFCajcD8E/RUWcSOPPj5mSnIM1427q0hScP9
            yw5kifK4unqi/urO6t4IPXVN304tm8E0Um/nw3t4NAxd7aCwc0fu6wnXIlb+aZeP
            TW14Qo8FlYqyMGu1XhKIHplPzTbSEeZsxv9cSfJHPwxhaLsiGKYRfslO4QIDAQAB
            AoGBALafYGGcOn0pK2QmyWzEIrid+oNrWKSGr98YstiopSeOTROI/2k9NhWITo8R
            0xz2L/EtI1VzbxX+RhcxQ8hoc19EaqQwVY01ZoN00uvYPrtoWLYKSZ9dXGReRVEH
            fNUHfOdFKj3iVy8yat7LPHr4cX9tYWiCxaXFNB2NnUY/p9uBAkEA8Wk0MqH8hnFn
            Zd8P6sA/k3uxDvClvfyh9V8CizNXVb+dTrDOnl3KEwhqYTkX413VCkiFsrHElMbL
            1i7NRPhWeQJBAN6n3pVzjaUSqhbkog1TstBhfl17nrd5qvNisTftHJ/d0NKJ9buH
            Hj7tk1MtHp1sqPa01yrevMqj9htmGi0fwakCQQDoHCLX2++UxEyKIiKHrzhxcSgY
            GUECnniKF0O22zJJe+af1leS5NJ54kmGGQLi1UEUlg4Wdd1wvoMV+AHdInjhAkBR
            /xJKiZaFTx1Sdvpy2/sDIJRPywHFYcoh/Zt0FB8xhJetoV7co8Lwu79Ap2IZ6XVD
            /Y8r24E9QyqUJoLHUWWZAkEAggmAJAhcJnytfBUUCyjjc36x7wn5LzaRqp77QQCa
            rHnyY28TwVjI/PpZgWXNdOeD4MrQuyjvr+n+5d7CCU8tYQ==
            -----END RSA PRIVATE KEY-----""";

    private static final String OIDC_PROVIDER_TOKEN_SIGNING_KEY = """
            -----BEGIN RSA PRIVATE KEY-----
            MIICXQIBAAKBgQC7FTvb+tIJN91iu2CFWXR9xCfPyyqalhCA5glhPdYNRbOPSE66
            uLLIiovjhe+QOc9mMalK+pGc5FXRo1MECy38/mfVeOGiHtqcGfO6cxJ4B3IapQM2
            wATWF8f6CtZqCgnXDK/noQHVcegDEf+FYrH1Tq7SWaYtE5gNmY7U7tVTwQIDAQAB
            AoGAc57Y4sgtvKK5AMbbDS7O7tcm36YpS2aJBpCkpWNpAcTdByVh+sYhQA1YDSJ+
            fv0rb3YrsXoQOg1n+Gre6HXcUht9pDAWeFQGLRDojV+FoiSeg4hULEve++pEdSBz
            K8wWyP0xgdkPJYvKWsp97ehKMn9gj1esIY/hYtm5KKjb6EECQQDfRNFHaMHr7avR
            x9Hv9lPm6Q4TSQDQCkk+LRXry8vyGicGXxdDMbq2HM6IcykD2dWDdDyrN4H8eh6d
            Bpvpv2kpAkEA1oJgR1MJ3FTL+4581DiawvsvH+Cy3le6iHwyN9qclM0ABgwNgFKu
            upssAwsHH88cy1ed2jLrQZJ6s2qSHSGw2QJBALBm6wMEndMOYabJvfFeKkRS9q/+
            CgpVVjEt5hf7WRPb3eGG2BZbAC5K7FOayVkljzDhcd3FaYpV4kImqqEwfqECQGNV
            2toMtTtINXIXyOzKDbkPcwIzHwHh5GrCAMtmvC4YRNOID1SGdY3Kv/XkzHbJhY8Q
            0vOxssoZ2CJvzpwY9vkCQQCS/iledrtBdaAk/lwphZUZcSh/qDn6on5sZnf+3DgZ
            PEw0pNKKUspeBvWwNMltYeRMw032ovZAmZewYQAqOB+a
            -----END RSA PRIVATE KEY-----""";

    private ExternalOAuthAuthenticationManager authManager;
    private OIDCIdentityProviderDefinition oidcConfig;
    private TokenEndpointBuilder tokenEndpointBuilder;
    private IdentityProvider<OIDCIdentityProviderDefinition> provider;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private OidcMetadataFetcher oidcMetadataFetcher;
    private JdbcScimGroupExternalMembershipManager externalMembershipManager;
    private UaaUserDatabase userDatabase;

    private KeyInfoService mockKeyInfoService() throws JOSEException {
        KeyInfoService keyInfoService = mock(KeyInfoService.class);
        KeyInfo keyInfo = mock(KeyInfo.class);
        JWSSigner signer = mock(JWSSigner.class);
        when(keyInfoService.getActiveKey()).thenReturn(keyInfo);
        when(keyInfoService.getKey("id")).thenReturn(keyInfo);
        when(keyInfo.algorithm()).thenReturn("RS256");
        when(keyInfo.getSigner()).thenReturn(signer);
        when(keyInfo.verifierCertificate()).thenReturn(Optional.of(X509CertUtils.parse(JwtHelperX5tTest.CERTIFICATE_1)));
        when(keyInfo.keyId()).thenReturn("id");
        when(signer.supportedJWSAlgorithms()).thenReturn(Set.of(JWSAlgorithm.RS256));
        when(signer.sign(any(), any())).thenReturn(new Base64URL("dummy"));
        return keyInfoService;
    }

    private IdentityProvider mockOidcIdentityProvider() throws MalformedURLException {
        IdentityProvider localIdp = mock(IdentityProvider.class);
        OIDCIdentityProviderDefinition localIdpConfig = mock(OIDCIdentityProviderDefinition.class);
        when(localIdpConfig.getRelyingPartyId()).thenReturn("identity");
        when(localIdpConfig.getTokenUrl()).thenReturn(URI.create("http://localhost:8080/uaa/oauth/token").toURL());
        when(localIdpConfig.getRelyingPartySecret()).thenReturn(null);
        when(localIdpConfig.getJwtClientAuthentication()).thenReturn(true);
        when(localIdpConfig.getScopes()).thenReturn(Arrays.asList("openid", "email"));
        when(localIdpConfig.isPasswordGrantEnabled()).thenReturn(true);
        when(localIdpConfig.isTokenExchangeEnabled()).thenReturn(true);
        when(localIdp.getOriginKey()).thenReturn("oidcprovider");
        when(localIdp.getConfig()).thenReturn(localIdpConfig);
        when(localIdp.getType()).thenReturn(OriginKeys.OIDC10);
        when(localIdp.isActive()).thenReturn(true);
        return localIdp;
    }

    @BeforeEach
    void beforeEach() throws Exception {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(ZONE_ID);
        IdentityZoneHolder.set(identityZone);

        identityProviderProvisioning = mock(IdentityProviderProvisioning.class);
        externalMembershipManager = mock(JdbcScimGroupExternalMembershipManager.class);
        userDatabase = mock(UaaUserDatabase.class);
        provider = new IdentityProvider<>();
        oidcConfig = new OIDCIdentityProviderDefinition();
        String oidcIssuerUrl = "http://issuer.com";
        oidcConfig.setIssuer(oidcIssuerUrl);
        oidcConfig.setTokenKey(OIDC_PROVIDER_TOKEN_SIGNING_KEY);
        oidcConfig.setRelyingPartyId("uaa-relying-party");
        Map<String, Object> externalGroupMapping = map(
                entry(GROUP_ATTRIBUTE_NAME, "roles")
        );
        oidcConfig.setAttributeMappings(externalGroupMapping);
        provider.setConfig(oidcConfig);
        when(identityProviderProvisioning.retrieveByOrigin(ORIGIN, ZONE_ID)).thenReturn(provider);
        tokenEndpointBuilder = new TokenEndpointBuilder(UAA_ISSUER_BASE_URL);
        oidcMetadataFetcher = new OidcMetadataFetcher(
                new StaleUrlCache(Duration.ofMinutes(2), new TimeServiceImpl(), 10, Ticker.disabledTicker()),
                new RestTemplate(),
                new RestTemplate()
        );
        authManager = new ExternalOAuthAuthenticationManager(identityProviderProvisioning, new IdentityZoneManagerImpl(), new RestTemplate(), new RestTemplate(), tokenEndpointBuilder, new KeyInfoService(UAA_ISSUER_BASE_URL), oidcMetadataFetcher);
        authManager.setExternalMembershipManager(externalMembershipManager);
        authManager.setUserDatabase(userDatabase);
    }

    @AfterEach
    void afterEach() {
        IdentityZoneHolder.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    void getExternalAuthenticationDetails_whenProviderHasSigningKey_throwsWhenIdTokenCannotBeValidated() {
        Map<String, Object> header = map(
                entry(HeaderParameterNames.ALGORITHM, JWSAlgorithm.RS256.getName()),
                entry(HeaderParameterNames.KEY_ID, OIDC_PROVIDER_KEY)
        );
        JWSSigner signer = new KeyInfo(OIDC_PROVIDER_KEY, OIDC_PROVIDER_TOKEN_SIGNING_KEY, DEFAULT_UAA_URL).getSigner();
        Map<String, Object> claims = map(
                entry(EXPIRY_IN_SECONDS, 0),
                entry(AUD, "uaa-relying-party"),
                entry(ISS, oidcConfig.getIssuer()),
                entry(EMAIL, "someuser@google.com")
        );
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", UAA_IDENTITY_ZONE_TOKEN_SIGNING_KEY));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken("thecode", ORIGIN, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
        assertThatThrownBy(() -> authManager.getExternalAuthenticationDetails(oidcAuthentication))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessage("Could not verify token signature.");
    }

    @Test
    void getExternalAuthenticationDetails_whenProviderIssuerMatchesUaaIssuer_throwsWhenIdTokenCannotBeValidated() {
        oidcConfig.setIssuer(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()));

        Map<String, Object> header = map(
                entry(HeaderParameterNames.ALGORITHM, JWSAlgorithm.RS256.getName()),
                entry(HeaderParameterNames.KEY_ID, "uaa-key")
        );
        JWSSigner signer = new KeyInfo("uaa-key", OIDC_PROVIDER_TOKEN_SIGNING_KEY, DEFAULT_UAA_URL).getSigner();
        Map<String, Object> claims = map(
                entry(EMAIL, "someuser@google.com")
        );
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", UAA_IDENTITY_ZONE_TOKEN_SIGNING_KEY));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken(null, ORIGIN, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
        assertThatThrownBy(() -> authManager.getExternalAuthenticationDetails(oidcAuthentication))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessage("Could not verify token signature.");
    }

    @Test
    void getExternalAuthenticationDetails_doesNotThrowWhenIdTokenIsValid() {
        Map<String, Object> header = map(
                entry(HeaderParameterNames.ALGORITHM, JWSAlgorithm.RS256.getName()),
                entry(HeaderParameterNames.KEY_ID, OIDC_PROVIDER_KEY)
        );
        JWSSigner signer = new KeyInfo(OIDC_PROVIDER_KEY, OIDC_PROVIDER_TOKEN_SIGNING_KEY, DEFAULT_UAA_URL).getSigner();
        Map<String, Object> claims = map(
                entry(EMAIL, "someuser@google.com"),
                entry(ISS, oidcConfig.getIssuer()),
                entry(AUD, "uaa-relying-party"),
                entry(EXPIRY_IN_SECONDS, ((int) (System.currentTimeMillis() / 1000L)) + 60),
                entry(SUB, "abc-def-asdf")
        );
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", UAA_IDENTITY_ZONE_TOKEN_SIGNING_KEY));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken(null, ORIGIN, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
        assertThatNoException().isThrownBy(() -> authManager.getExternalAuthenticationDetails(oidcAuthentication));
    }

    @Test
    void getExternalAuthenticationDetails_whenUaaToken_doesNotThrowWhenIdTokenIsValid() {
        oidcConfig.setIssuer(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()));
        Map<String, Object> header = map(
                entry(HeaderParameterNames.ALGORITHM, JWSAlgorithm.RS256.getName()),
                entry(HeaderParameterNames.KEY_ID, "uaa-key")
        );
        JWSSigner signer = new KeyInfo("uaa-key", UAA_IDENTITY_ZONE_TOKEN_SIGNING_KEY, DEFAULT_UAA_URL).getSigner();
        Map<String, Object> claims = map(
                entry(EMAIL, "someuser@google.com"),
                entry(ISS, oidcConfig.getIssuer()),
                entry(AUD, "uaa-relying-party"),
                entry(EXPIRY_IN_SECONDS, ((int) (System.currentTimeMillis() / 1000L)) + 60),
                entry(SUB, "abc-def-asdf")
        );
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", UAA_IDENTITY_ZONE_TOKEN_SIGNING_KEY));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken("thecode", ORIGIN, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
        assertThatNoException().isThrownBy(() -> authManager.getExternalAuthenticationDetails(oidcAuthentication));
    }

    @Test
    void getExternalAuthenticationDetails_whenUaaToken_mapRoleAsExplicitToScopeWhenIdTokenIsValid() {
        oidcConfig.setIssuer(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()));
        Map<String, Object> header = map(
                entry(HeaderParameterNames.ALGORITHM, JWSAlgorithm.RS256.getName()),
                entry(HeaderParameterNames.KEY_ID, "uaa-key")
        );
        JWSSigner signer = new KeyInfo("uaa-key", UAA_IDENTITY_ZONE_TOKEN_SIGNING_KEY, DEFAULT_UAA_URL).getSigner();
        List<String> roles = Arrays.asList("manager.us", "manager.eu");
        Map<String, Object> claims = map(
                entry(EMAIL, "someuser@google.com"),
                entry(ISS, oidcConfig.getIssuer()),
                entry(AUD, "uaa-relying-party"),
                entry(ROLES, roles),
                entry(EXPIRY_IN_SECONDS, ((int) (System.currentTimeMillis() / 1000L)) + 60),
                entry(SUB, "abc-def-asdf")
        );
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", UAA_IDENTITY_ZONE_TOKEN_SIGNING_KEY));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);
        // When
        oidcConfig.setGroupMappingMode(AbstractExternalOAuthIdentityProviderDefinition.OAuthGroupMappingMode.EXPLICITLY_MAPPED);
        provider.setConfig(oidcConfig);
        when(identityProviderProvisioning.retrieveByOrigin(ORIGIN, ZONE_ID)).thenReturn(provider);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken("thecode", ORIGIN, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
        ExternalOAuthAuthenticationManager.AuthenticationData authenticationData = authManager.getExternalAuthenticationDetails(oidcAuthentication);
        assertThat(authenticationData).isNotNull();
        assertThat(authenticationData.getAuthorities()).isEmpty();
    }

    @Test
    void getExternalAuthenticationDetails_whenUaaToken_mapRoleAsScopeToScopeWhenIdTokenIsValid() {
        oidcConfig.setIssuer(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()));
        Map<String, Object> header = map(
                entry(HeaderParameterNames.ALGORITHM, JWSAlgorithm.RS256.getName()),
                entry(HeaderParameterNames.KEY_ID, "uaa-key")
        );
        JWSSigner signer = new KeyInfo("uaa-key", UAA_IDENTITY_ZONE_TOKEN_SIGNING_KEY, DEFAULT_UAA_URL).getSigner();
        Set<String> roles = new HashSet<>(Arrays.asList("manager.us", "manager.eu"));
        Map<String, Object> claims = map(
                entry(EMAIL, "someuser@google.com"),
                entry(ISS, oidcConfig.getIssuer()),
                entry(AUD, "uaa-relying-party"),
                entry(ROLES, roles),
                entry(EXPIRY_IN_SECONDS, ((int) (System.currentTimeMillis() / 1000L)) + 60),
                entry(SUB, "abc-def-asdf")
        );
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", UAA_IDENTITY_ZONE_TOKEN_SIGNING_KEY));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);
        // When
        oidcConfig.setGroupMappingMode(AbstractExternalOAuthIdentityProviderDefinition.OAuthGroupMappingMode.AS_SCOPES);
        provider.setConfig(oidcConfig);
        when(identityProviderProvisioning.retrieveByOrigin(ORIGIN, ZONE_ID)).thenReturn(provider);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken("thecode", ORIGIN, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
        ExternalOAuthAuthenticationManager.AuthenticationData authenticationData = authManager.getExternalAuthenticationDetails(oidcAuthentication);
        assertThat(authenticationData).isNotNull();
        assertThat(authenticationData.getAuthorities()).hasSize(2);
        Set<String> authicatedAuthorities = AuthorityUtils.authorityListToSet(authenticationData.getAuthorities());
        assertThat(roles.toArray()).contains(authicatedAuthorities.toArray());
        // no exception expected, but same array content in authority list
    }

    @Test
    void getExternalAuthenticationDetails_whenUaaToken_internalAndExternalRolesAreDifferentViaExternalGroupMapping() {
        oidcConfig.setIssuer(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()));
        Map<String, Object> header = map(
                entry(HeaderParameterNames.ALGORITHM, JWSAlgorithm.RS256.getName()),
                entry(HeaderParameterNames.KEY_ID, "uaa-key")
        );
        JWSSigner signer = new KeyInfo("uaa-key", UAA_IDENTITY_ZONE_TOKEN_SIGNING_KEY, DEFAULT_UAA_URL).getSigner();
        Set<String> roles = new HashSet<>(Arrays.asList("manager.us", "manager.eu"));
        Map<String, Object> claims = map(
                entry(EMAIL, "someuser@google.com"),
                entry(ISS, oidcConfig.getIssuer()),
                entry(AUD, "uaa-relying-party"),
                entry(ROLES, roles),
                entry(EXPIRY_IN_SECONDS, ((int) (System.currentTimeMillis() / 1000L)) + 60),
                entry(SUB, "abc-def-asdf")
        );
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", UAA_IDENTITY_ZONE_TOKEN_SIGNING_KEY));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);
        // When
        oidcConfig.setGroupMappingMode(AbstractExternalOAuthIdentityProviderDefinition.OAuthGroupMappingMode.EXPLICITLY_MAPPED);
        provider.setConfig(oidcConfig);
        when(identityProviderProvisioning.retrieveByOrigin(ORIGIN, ZONE_ID)).thenReturn(provider);

        ScimGroupExternalMember groupMap1 = new ScimGroupExternalMember("group-1", "manager.us");
        groupMap1.setDisplayName("cloud_controller.read");
        ScimGroupExternalMember groupMap2 = new ScimGroupExternalMember("group-2", "manager.eu");
        groupMap2.setDisplayName("cloud_controller.write");
        ScimGroupExternalMember groupMap3 = new ScimGroupExternalMember("group-3", "manager.eu");
        groupMap3.setDisplayName("cloud_controller.delete");
        when(externalMembershipManager.getExternalGroupMapsByExternalGroup(eq("manager.us"), any(), any())).thenReturn(List.of(groupMap1));
        when(externalMembershipManager.getExternalGroupMapsByExternalGroup(eq("manager.eu"), any(), any())).thenReturn(List.of(groupMap2, groupMap3));

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken("thecode", ORIGIN, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
        ExternalOAuthAuthenticationManager.AuthenticationData authenticationData = authManager.getExternalAuthenticationDetails(oidcAuthentication);
        assertThat(authenticationData).isNotNull();
        //external authorities
        assertThat(authenticationData.getExternalAuthorities()).hasSize(2);
        Set<String> externalAuthorities = AuthorityUtils.authorityListToSet(authenticationData.getExternalAuthorities());
        assertThat(externalAuthorities).containsAll(roles);
        //internal (mapped) authorities
        assertThat(authenticationData.getAuthorities()).hasSize(3);
        Set<String> internalAuthorities = AuthorityUtils.authorityListToSet(authenticationData.getAuthorities());
        assertThat(Set.of("cloud_controller.read", "cloud_controller.write", "cloud_controller.delete")).containsAll(internalAuthorities);
    }

    @Test
    void getExternalAuthenticationDetails_whenUaaToken_ExternalRolesAreFiltered() {
        oidcConfig.setIssuer(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()));
        Map<String, Object> header = map(
                entry(HeaderParameterNames.ALGORITHM, JWSAlgorithm.RS256.getName()),
                entry(HeaderParameterNames.KEY_ID, "uaa-key")
        );
        JWSSigner signer = new KeyInfo("uaa-key", UAA_IDENTITY_ZONE_TOKEN_SIGNING_KEY, DEFAULT_UAA_URL).getSigner();
        Set<String> roles = new HashSet<>(Arrays.asList("manager.us", "manager.eu"));
        Map<String, Object> claims = map(
                entry(EMAIL, "someuser@google.com"),
                entry(ISS, oidcConfig.getIssuer()),
                entry(AUD, "uaa-relying-party"),
                entry(ROLES, roles),
                entry(EXPIRY_IN_SECONDS, ((int) (System.currentTimeMillis() / 1000L)) + 60),
                entry(SUB, "abc-def-asdf")
        );
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", UAA_IDENTITY_ZONE_TOKEN_SIGNING_KEY));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);
        // When
        oidcConfig.setGroupMappingMode(AbstractExternalOAuthIdentityProviderDefinition.OAuthGroupMappingMode.EXPLICITLY_MAPPED);
        oidcConfig.setExternalGroupsWhitelist(List.of("manager.us"));
        provider.setConfig(oidcConfig);
        when(identityProviderProvisioning.retrieveByOrigin(ORIGIN, ZONE_ID)).thenReturn(provider);

        ScimGroupExternalMember groupMap1 = new ScimGroupExternalMember("group-1", "manager.us");
        groupMap1.setDisplayName("cloud_controller.read");
        ScimGroupExternalMember groupMap2 = new ScimGroupExternalMember("group-2", "manager.eu");
        groupMap2.setDisplayName("cloud_controller.write");
        ScimGroupExternalMember groupMap3 = new ScimGroupExternalMember("group-3", "manager.eu");
        groupMap3.setDisplayName("cloud_controller.delete");
        when(externalMembershipManager.getExternalGroupMapsByExternalGroup(eq("manager.us"), any(), any())).thenReturn(List.of(groupMap1));
        when(externalMembershipManager.getExternalGroupMapsByExternalGroup(eq("manager.eu"), any(), any())).thenReturn(List.of(groupMap2, groupMap3));

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken("thecode", ORIGIN, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
        ExternalOAuthAuthenticationManager.AuthenticationData authenticationData = authManager.getExternalAuthenticationDetails(oidcAuthentication);
        assertThat(authenticationData).isNotNull();
        //external authorities
        assertThat(authenticationData.getExternalAuthorities()).hasSize(1);
        Set<String> externalAuthorities = AuthorityUtils.authorityListToSet(authenticationData.getExternalAuthorities());
        assertThat(externalAuthorities).containsExactly("manager.us");
        //internal (mapped) authorities
        assertThat(authenticationData.getAuthorities()).hasSize(1);
        Set<String> internalAuthorities = AuthorityUtils.authorityListToSet(authenticationData.getAuthorities());
        assertThat(Set.of("cloud_controller.read")).containsAll(internalAuthorities);
    }

    @Test
    void getExternalAuthenticationDetails_whenUaaToken_mapRoleAsScopeToScopeWhenIdTokenIsValid_AndFilterManagerRolesOnly() {
        oidcConfig.setIssuer(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()));
        Map<String, Object> header = map(
                entry(HeaderParameterNames.ALGORITHM, JWSAlgorithm.RS256.getName()),
                entry(HeaderParameterNames.KEY_ID, "uaa-key")
        );
        JWSSigner signer = new KeyInfo("uaa-key", UAA_IDENTITY_ZONE_TOKEN_SIGNING_KEY, DEFAULT_UAA_URL).getSigner();
        Set<String> roles = new HashSet<>(Arrays.asList("manager.us", "manager.eu", "uaa.admin", "uaa.user", "idp.write", "employee.us"));
        Map<String, Object> claims = map(
                entry(EMAIL, "someuser@google.com"),
                entry(ISS, oidcConfig.getIssuer()),
                entry(AUD, "uaa-relying-party"),
                entry(ROLES, roles),
                entry(EXPIRY_IN_SECONDS, ((int) (System.currentTimeMillis() / 1000L)) + 60),
                entry(SUB, "abc-def-asdf")
        );
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", UAA_IDENTITY_ZONE_TOKEN_SIGNING_KEY));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);
        // When
        oidcConfig.setGroupMappingMode(AbstractExternalOAuthIdentityProviderDefinition.OAuthGroupMappingMode.AS_SCOPES);
        oidcConfig.setExternalGroupsWhitelist(List.of("manager.*"));
        provider.setConfig(oidcConfig);
        when(identityProviderProvisioning.retrieveByOrigin(ORIGIN, ZONE_ID)).thenReturn(provider);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken("thecode", ORIGIN, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
        ExternalOAuthAuthenticationManager.AuthenticationData authenticationData = authManager.getExternalAuthenticationDetails(oidcAuthentication);
        assertThat(authenticationData).isNotNull();
        assertThat(authenticationData.getAuthorities()).hasSize(2);
        Set<String> authicatedAuthorities = AuthorityUtils.authorityListToSet(authenticationData.getAuthorities());
        assertThat(Set.of("manager.us", "manager.eu").toArray()).contains(authicatedAuthorities.toArray());
        // no exception expected, but same array content in authority list
    }

    @Test
    void getUser_doesNotThrowWhenIdTokenMappingIsArray() {
        Map<String, Object> header = map(
                entry(HeaderParameterNames.ALGORITHM, JWSAlgorithm.RS256.getName()),
                entry(HeaderParameterNames.KEY_ID, OIDC_PROVIDER_KEY)
        );
        JWSSigner signer = new KeyInfo(OIDC_PROVIDER_KEY, OIDC_PROVIDER_TOKEN_SIGNING_KEY, DEFAULT_UAA_URL).getSigner();
        Map<String, Object> claims = map(
                entry("external_family_name", Collections.emptyList()),
                entry("external_given_name", List.of("bar", "bar")),
                entry("external_email", List.of("foo@bar.org", "foo@bar.org")),
                entry(ISS, oidcConfig.getIssuer()),
                entry(AUD, "uaa-relying-party"),
                entry(EXPIRY_IN_SECONDS, ((int) (System.currentTimeMillis() / 1000L)) + 60),
                entry(SUB, "abc-def-asdf")
        );
        Map<String, Object> externalGroupMapping = map(
                entry(USER_NAME_ATTRIBUTE_NAME, "external_email"),
                entry(FAMILY_NAME_ATTRIBUTE_NAME, "external_family_name"),
                entry(ExternalIdentityProviderDefinition.GIVEN_NAME_ATTRIBUTE_NAME, "external_given_name"),
                entry(ExternalIdentityProviderDefinition.EMAIL_ATTRIBUTE_NAME, "external_email"),
                entry(ExternalIdentityProviderDefinition.PHONE_NUMBER_ATTRIBUTE_NAME, "external_phone")
        );
        oidcConfig.setAttributeMappings(externalGroupMapping);
        provider.setConfig(oidcConfig);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", UAA_IDENTITY_ZONE_TOKEN_SIGNING_KEY));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken(null, ORIGIN, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
        UaaUser uaaUser = authManager.getUser(oidcAuthentication, authManager.getExternalAuthenticationDetails(oidcAuthentication));
        assertThat(uaaUser).isNotNull();
        assertThat(uaaUser.getFamilyName()).isNull();
        assertThat(uaaUser.getGivenName()).isEqualTo("bar");
        assertThat(uaaUser.getEmail()).isEqualTo("foo@bar.org");
        assertThat(uaaUser.getUsername()).isEqualTo("foo@bar.org");
    }

    @Test
    void getUser_doesThrowWhenIdTokenMappingIsAmbiguous() {
        Map<String, Object> header = map(
                entry(HeaderParameterNames.ALGORITHM, JWSAlgorithm.RS256.getName()),
                entry(HeaderParameterNames.KEY_ID, OIDC_PROVIDER_KEY)
        );
        JWSSigner signer = new KeyInfo(OIDC_PROVIDER_KEY, OIDC_PROVIDER_TOKEN_SIGNING_KEY, DEFAULT_UAA_URL).getSigner();
        Map<String, Object> claims = map(
                entry("external_family_name", Arrays.asList("bar", "baz")),
                entry(ISS, oidcConfig.getIssuer()),
                entry(AUD, "uaa-relying-party"),
                entry(EXPIRY_IN_SECONDS, ((int) (System.currentTimeMillis() / 1000L)) + 60),
                entry(SUB, "abc-def-asdf")
        );
        Map<String, Object> externalGroupMapping = map(
                entry(FAMILY_NAME_ATTRIBUTE_NAME, "external_family_name")
        );
        oidcConfig.setAttributeMappings(externalGroupMapping);
        provider.setConfig(oidcConfig);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", UAA_IDENTITY_ZONE_TOKEN_SIGNING_KEY));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken(null, ORIGIN, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
        ExternalOAuthAuthenticationManager.AuthenticationData externalAuthenticationDetails = authManager.getExternalAuthenticationDetails(oidcAuthentication);
        assertThatThrownBy(() -> authManager.getUser(oidcAuthentication, externalAuthenticationDetails))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Claim mapping for family_name attribute is ambiguous");
    }

    @Test
    void getUser_doesThrowWhenIdTokenMappingIsWrongType() {
        Map<String, Object> header = map(
                entry(HeaderParameterNames.ALGORITHM, JWSAlgorithm.RS256.getName()),
                entry(HeaderParameterNames.KEY_ID, OIDC_PROVIDER_KEY)
        );
        JWSSigner signer = new KeyInfo("uaa-key", OIDC_PROVIDER_TOKEN_SIGNING_KEY, DEFAULT_UAA_URL).getSigner();
        Map<String, Object> entryMap = map(
                entry("external_map_name", Arrays.asList("bar", "baz"))
        );
        Map<String, Object> claims = map(
                entry("external_family_name", entryMap),
                entry(ISS, oidcConfig.getIssuer()),
                entry(AUD, "uaa-relying-party"),
                entry(EXPIRY_IN_SECONDS, ((int) (System.currentTimeMillis() / 1000L)) + 60),
                entry(SUB, "abc-def-asdf")
        );
        Map<String, Object> externalGroupMapping = map(
                entry(FAMILY_NAME_ATTRIBUTE_NAME, "external_family_name")
        );
        oidcConfig.setAttributeMappings(externalGroupMapping);
        provider.setConfig(oidcConfig);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", UAA_IDENTITY_ZONE_TOKEN_SIGNING_KEY));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken(null, ORIGIN, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
        ExternalOAuthAuthenticationManager.AuthenticationData externalAuthenticationDetails = authManager.getExternalAuthenticationDetails(oidcAuthentication);
        assertThatThrownBy(() -> authManager.getUser(oidcAuthentication, externalAuthenticationDetails))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("External token attribute external_family_name cannot be mapped to user attribute family_name");
    }

    @Test
    void populateAuthenticationAttributes_setsIdpIdTokenAndExternalGroups() {
        UaaAuthentication authentication = new UaaAuthentication(new UaaPrincipal("user-guid", "marissa", "marissa@test.org", "uaa", "", ""), Collections.emptyList(), null);
        Map<String, Object> header = map(
                entry(HeaderParameterNames.ALGORITHM, JWSAlgorithm.RS256.getName()),
                entry(HeaderParameterNames.KEY_ID, OIDC_PROVIDER_KEY)
        );
        JWSSigner signer = new KeyInfo("uaa-key", OIDC_PROVIDER_TOKEN_SIGNING_KEY, DEFAULT_UAA_URL).getSigner();
        Map<String, Object> entryMap = map(
                entry("external_map_name", Arrays.asList("bar", "baz"))
        );
        Map<String, Object> claims = map(
                entry("external_family_name", entryMap),
                entry(ISS, oidcConfig.getIssuer()),
                entry(AUD, "uaa-relying-party"),
                entry(EXPIRY_IN_SECONDS, ((int) (System.currentTimeMillis() / 1000L)) + 60),
                entry(SUB, "abc-def-asdf")
        );
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", UAA_IDENTITY_ZONE_TOKEN_SIGNING_KEY));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);
        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken(null, ORIGIN, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
        ExternalOAuthAuthenticationManager.AuthenticationData authenticationData = authManager.getExternalAuthenticationDetails(oidcAuthentication);
        authenticationData.setExternalAuthorities(List.of(new SimpleGrantedAuthority("uaa-authorities")));
        authManager.populateAuthenticationAttributes(authentication, oidcAuthentication, authenticationData);
        assertThat(authentication.getIdpIdToken()).isEqualTo(idTokenJwt);
        assertThat(authentication.getExternalGroups()).containsAll(List.of("uaa-authorities"));
    }

    @Test
    void getClaimsFromToken_setsIdToken() {
        Map<String, Object> header = map(
                entry(HeaderParameterNames.ALGORITHM, JWSAlgorithm.RS256.getName()),
                entry(HeaderParameterNames.KEY_ID, OIDC_PROVIDER_KEY)
        );
        JWSSigner signer = new KeyInfo("uaa-key", OIDC_PROVIDER_TOKEN_SIGNING_KEY, DEFAULT_UAA_URL).getSigner();
        Map<String, Object> entryMap = map(
                entry("external_map_name", Arrays.asList("bar", "baz"))
        );
        Map<String, Object> claims = map(
                entry("external_family_name", entryMap),
                entry(ISS, oidcConfig.getIssuer()),
                entry(AUD, "uaa-relying-party"),
                entry(EXPIRY_IN_SECONDS, ((int) (System.currentTimeMillis() / 1000L)) + 60),
                entry(SUB, "abc-def-asdf")
        );
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);
        ExternalOAuthCodeToken codeToken = new ExternalOAuthCodeToken("thecode", ORIGIN, "http://google.com", null, "accesstoken", "signedrequest");

        authManager = new ExternalOAuthAuthenticationManager(identityProviderProvisioning, new IdentityZoneManagerImpl(), new RestTemplate(), new RestTemplate(), tokenEndpointBuilder, new KeyInfoService(UAA_ISSUER_BASE_URL), null) {
            @Override
            protected <T extends AbstractExternalOAuthIdentityProviderDefinition<T>> String getTokenFromCode(
                    ExternalOAuthCodeToken codeToken,
                    IdentityProvider<T> config
            ) {
                return idTokenJwt;
            }
        };

        final IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> idp = new IdentityProvider<>();
        idp.setConfig(oidcConfig);

        authManager.getClaimsFromToken(codeToken, idp);
        assertThat(codeToken.getIdToken()).isEqualTo(idTokenJwt);
    }

    @Test
    void fetchOidcMetadata() throws OidcMetadataFetchingException {
        OIDCIdentityProviderDefinition mockedProviderDefinition = mock(OIDCIdentityProviderDefinition.class);
        OidcMetadataFetcher mockedOidcMetadataFetcher = mock(OidcMetadataFetcher.class);
        authManager = new ExternalOAuthAuthenticationManager(identityProviderProvisioning, new IdentityZoneManagerImpl(), new RestTemplate(), new RestTemplate(), tokenEndpointBuilder, new KeyInfoService(UAA_ISSUER_BASE_URL), mockedOidcMetadataFetcher);
        doThrow(new OidcMetadataFetchingException("error")).when(mockedOidcMetadataFetcher).fetchMetadataAndUpdateDefinition(mockedProviderDefinition);
        assertThatNoException().isThrownBy(() -> authManager.fetchMetadataAndUpdateDefinition(mockedProviderDefinition));
    }

    @Test
    void oidcPasswordGrantProviderFailedInOidcMetadataUpdate() {
        IdentityProvider localIdp = mock(IdentityProvider.class);
        OIDCIdentityProviderDefinition localIdpConfig = mock(OIDCIdentityProviderDefinition.class);
        when(localIdp.getOriginKey()).thenReturn("oidcprovider");
        when(localIdp.getType()).thenReturn(OriginKeys.OIDC10);
        when(localIdp.isActive()).thenReturn(true);
        when(localIdp.getConfig()).thenReturn(localIdpConfig);
        when(localIdpConfig.isPasswordGrantEnabled()).thenReturn(true);
        when(localIdpConfig.getRelyingPartyId()).thenReturn("oidcprovider");
        when(localIdpConfig.getRelyingPartySecret()).thenReturn("");

        try {
            authManager.oauthTokenRequest(mock(UaaAuthenticationDetails.class), localIdp, GRANT_TYPE_PASSWORD, new LinkedMaskingMultiValueMap<>());
            fail("");
        } catch (ProviderConfigurationException e) {
            assertThat(e.getMessage()).isEqualTo("External OpenID Connect metadata is missing after discovery update.");
        }
    }

    @Test
    void oidcPasswordGrantProviderNoRelyingPartyCredentials() {
        IdentityProvider localIdp = mock(IdentityProvider.class);
        OIDCIdentityProviderDefinition idpConfig = mock(OIDCIdentityProviderDefinition.class);
        when(localIdp.getOriginKey()).thenReturn("oidcprovider");
        when(localIdp.getConfig()).thenReturn(idpConfig);
        when(localIdp.getType()).thenReturn(OriginKeys.OIDC10);
        when(localIdp.isActive()).thenReturn(true);
        when(idpConfig.isPasswordGrantEnabled()).thenReturn(true);

        try {
            authManager.oauthTokenRequest(mock(UaaAuthenticationDetails.class), localIdp, GRANT_TYPE_PASSWORD, new LinkedMaskingMultiValueMap<>());
            fail("");
        } catch (ProviderConfigurationException e) {
            assertThat(e.getMessage()).isEqualTo("External OpenID Connect provider configuration is missing relyingPartyId.");
        }
    }


    @Test
    void getOidcProxyIdpForTokenExchangeSuccess() throws MalformedURLException {
        IdentityProvider<OIDCIdentityProviderDefinition> idp = mockOidcIdentityProvider();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("login_hint", new UaaLoginHint("idp").toString());
        UsernamePasswordAuthenticationToken uaaAuthentication = mock(UsernamePasswordAuthenticationToken.class);
        UaaAuthenticationDetails uaaAuthenticationDetails = mock(UaaAuthenticationDetails.class);
        UaaClient uaaClient = mock(UaaClient.class);
        doReturn(uaaClient).when(uaaAuthentication).getPrincipal();
        doReturn(Map.of(ClientConstants.ALLOWED_PROVIDERS, List.of("uaa", "idp"))).when(uaaClient).getAdditionalInformation();
        when(uaaAuthentication.getDetails()).thenReturn(uaaAuthenticationDetails);
        when(identityProviderProvisioning.retrieveByOrigin(any(), any())).thenReturn(idp);
        when(idp.getOriginKey()).thenReturn("idp");
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        assertThat(authManager.getOidcProxyIdpForTokenExchange(request)).isEqualTo(idp);
    }

    @Test
    void getOidcProxyIdpForTokenExchangeNotEnabled() throws MalformedURLException {
        IdentityProvider<OIDCIdentityProviderDefinition> idp = mockOidcIdentityProvider();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("login_hint", new UaaLoginHint("idp").toString());
        UsernamePasswordAuthenticationToken uaaAuthentication = mock(UsernamePasswordAuthenticationToken.class);
        UaaAuthenticationDetails uaaAuthenticationDetails = mock(UaaAuthenticationDetails.class);
        UaaClient uaaClient = mock(UaaClient.class);
        doReturn(uaaClient).when(uaaAuthentication).getPrincipal();
        doReturn(null).when(uaaClient).getAdditionalInformation();
        when(uaaAuthentication.getDetails()).thenReturn(uaaAuthenticationDetails);
        when(idp.getType()).thenReturn(OriginKeys.OAUTH20);
        when(identityProviderProvisioning.retrieveByOrigin(any(), any())).thenReturn(idp);
        when(idp.getOriginKey()).thenReturn("idp");
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        assertThat(authManager.getOidcProxyIdpForTokenExchange(request)).isNull();
    }

    @Test
    void getOidcProxyIdpForTokenExchangeDbException() throws MalformedURLException {
        IdentityProvider<OIDCIdentityProviderDefinition> idp = mockOidcIdentityProvider();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("login_hint", new UaaLoginHint("idp").toString());
        UaaAuthentication uaaAuthentication = mock(UaaAuthentication.class);
        UaaAuthenticationDetails uaaAuthenticationDetails = mock(UaaAuthenticationDetails.class);
        when(uaaAuthentication.getDetails()).thenReturn(uaaAuthenticationDetails);
        when(identityProviderProvisioning.retrieveByOrigin(any(), any())).thenThrow(new EmptyResultDataAccessException(1));
        when(idp.getOriginKey()).thenReturn("idp");
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        assertThat(authManager.getOidcProxyIdpForTokenExchange(request)).isNull();
    }

    @Test
    void getOidcProxyIdpForTokenExchangeNoResult() throws MalformedURLException {
        IdentityProvider<OIDCIdentityProviderDefinition> idp = mockOidcIdentityProvider();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("login_hint", new UaaLoginHint("idp").toString());
        UaaAuthentication uaaAuthentication = mock(UaaAuthentication.class);
        UaaAuthenticationDetails uaaAuthenticationDetails = mock(UaaAuthenticationDetails.class);
        when(uaaAuthentication.getDetails()).thenReturn(uaaAuthenticationDetails);
        when(identityProviderProvisioning.retrieveByOrigin(any(), any())).thenReturn(null);
        when(idp.getOriginKey()).thenReturn("idp");
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        assertThat(authManager.getOidcProxyIdpForTokenExchange(request)).isNull();
    }

    @Test
    void getAllowedProvidersSuccess() {
        UsernamePasswordAuthenticationToken uaaAuthentication = mock(UsernamePasswordAuthenticationToken.class);
        UaaClient uaaClient = mock(UaaClient.class);
        doReturn(uaaClient).when(uaaAuthentication).getPrincipal();
        doReturn(Map.of(ClientConstants.ALLOWED_PROVIDERS, List.of("uaa"))).when(uaaClient).getAdditionalInformation();
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        assertThat(authManager.getAllowedProviders()).isInstanceOf(List.class).hasSize(1);
    }

    @Test
    void getAllowedProvidersNull() {
        UsernamePasswordAuthenticationToken uaaAuthentication = mock(UsernamePasswordAuthenticationToken.class);
        UaaClient uaaClient = mock(UaaClient.class);
        doReturn(uaaClient).when(uaaAuthentication).getPrincipal();
        doReturn(null).when(uaaClient).getAdditionalInformation();
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        assertThat(authManager.getAllowedProviders()).isNull();
    }

    @Test
    void getAllowedProvidersNoAuthentication() {
        assertThatThrownBy(() -> authManager.getAllowedProviders()).isInstanceOf(BadCredentialsException.class)
                .hasMessage("No client authentication found.");
    }

    @Test
    void oidcPasswordGrant_requireAuthenticationStatement() {
        IdentityProvider<OIDCIdentityProviderDefinition> localIdp = new IdentityProvider<>();
        localIdp.setOriginKey(new AlphanumericRandomValueStringGenerator(8).generate().toLowerCase());
        OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition().setRelyingPartyId("client-id");
        localIdp.setConfig(config);

        assertThatThrownBy(() -> authManager.oauthTokenRequest(mock(UaaAuthenticationDetails.class), localIdp, GRANT_TYPE_PASSWORD, new LinkedMaskingMultiValueMap<>()))
                .isInstanceOf(ProviderConfigurationException.class)
                .hasMessage("External OpenID Connect provider configuration is missing relyingPartySecret, jwtClientAuthentication or authMethod.");
    }

    @Test
    void oidcPasswordGrantProviderJwtClientCredentials() throws ParseException, JOSEException, MalformedURLException {
        // Given
        KeyInfoService keyInfoService = mockKeyInfoService();
        ResponseEntity responseEntity = mock(ResponseEntity.class);
        /* HTTP mock */
        RestTemplate rt = mock(RestTemplate.class);
        when(rt.exchange(eq("http://localhost:8080/uaa/oauth/token"), eq(HttpMethod.POST), any(HttpEntity.class), any(ParameterizedTypeReference.class))).thenReturn(responseEntity);
        when(responseEntity.hasBody()).thenReturn(true);
        when(responseEntity.getBody()).thenReturn(Map.of("id_token", "dummy"));
        authManager = new ExternalOAuthAuthenticationManager(identityProviderProvisioning, new IdentityZoneManagerImpl(), rt, rt, tokenEndpointBuilder, keyInfoService, oidcMetadataFetcher);

        // When
        authManager.oauthTokenRequest(null, mockOidcIdentityProvider(), GRANT_TYPE_PASSWORD, new LinkedMaskingMultiValueMap<>());
        ArgumentCaptor<HttpEntity> httpEntityArgumentCaptor = ArgumentCaptor.forClass(HttpEntity.class);

        // Then
        verify(rt, times(1)).exchange(eq("http://localhost:8080/uaa/oauth/token"), eq(HttpMethod.POST), httpEntityArgumentCaptor.capture(), eq(new ParameterizedTypeReference<Map<String, String>>() {
        }));
        HttpEntity httpEntity = httpEntityArgumentCaptor.getValue();
        LinkedMultiValueMap<String, Object> httpEntityBody = (LinkedMultiValueMap) httpEntity.getBody();
        assertThat(httpEntityBody).containsKey("client_assertion")
                .containsKey("client_assertion_type")
                .containsEntry("client_assertion_type", Collections.singletonList(JwtClientAuthentication.GRANT_TYPE))
                .containsKey("scope")
                .containsEntry("scope", Collections.singletonList("openid email"));
        /* verify client assertion according OIDC private_key_jwt */
        assertThat(httpEntityBody).isNotNull();
        final List<Object> clientAssertion = httpEntityBody.get("client_assertion");
        assertThat(clientAssertion).isNotNull().isNotEmpty();
        JWTClaimsSet jwtClaimsSet = JWTParser.parse((String) clientAssertion.getFirst()).getJWTClaimsSet();
        assertThat(jwtClaimsSet.getAudience()).isEqualTo(Collections.singletonList("http://localhost:8080/uaa/oauth/token"));
        assertThat(jwtClaimsSet.getSubject()).isEqualTo("identity");
        assertThat(jwtClaimsSet.getIssuer()).isEqualTo("identity");
    }

    @Test
    void oidcJwtBearerProviderJwtClientCredentials() throws ParseException, JOSEException, MalformedURLException {
        // Given
        KeyInfoService keyInfoService = mockKeyInfoService();
        ResponseEntity responseEntity = mock(ResponseEntity.class);
        UaaAuthenticationDetails uaaAuthenticationDetails = mock(UaaAuthenticationDetails.class);
        /* HTTP mock */
        RestTemplate rt = mock(RestTemplate.class);
        when(rt.exchange(eq("http://localhost:8080/uaa/oauth/token"), eq(HttpMethod.POST), any(HttpEntity.class), any(ParameterizedTypeReference.class))).thenReturn(responseEntity);
        when(responseEntity.hasBody()).thenReturn(true);
        when(responseEntity.getBody()).thenReturn(Map.of("id_token", "dummy"));
        authManager = new ExternalOAuthAuthenticationManager(identityProviderProvisioning, new IdentityZoneManagerImpl(), rt, rt, tokenEndpointBuilder, keyInfoService, oidcMetadataFetcher);

        // When
        assertThat(authManager.oidcJwtBearerGrant(uaaAuthenticationDetails, mockOidcIdentityProvider() , "proxy-token")).isEqualTo("dummy");
        ArgumentCaptor<HttpEntity> httpEntityArgumentCaptor = ArgumentCaptor.forClass(HttpEntity.class);

        // Then
        verify(rt, times(1)).exchange(eq("http://localhost:8080/uaa/oauth/token"), eq(HttpMethod.POST), httpEntityArgumentCaptor.capture(), eq(new ParameterizedTypeReference<Map<String, String>>() {
        }));
        HttpEntity httpEntity = httpEntityArgumentCaptor.getValue();
        LinkedMultiValueMap<String, Object> httpEntityBody = (LinkedMultiValueMap) httpEntity.getBody();
        assertThat(httpEntityBody).containsKey("client_assertion")
                .containsKey("client_assertion_type")
                .containsEntry("client_assertion_type", Collections.singletonList(JwtClientAuthentication.GRANT_TYPE))
                .containsEntry("assertion", Collections.singletonList("proxy-token"))
                .containsEntry("grant_type", Collections.singletonList(GRANT_TYPE_JWT_BEARER))
                .containsKey("scope")
                .containsEntry("scope", Collections.singletonList("openid email"));
        /* verify client assertion according OIDC private_key_jwt */
        assertThat(httpEntityBody).isNotNull();
        final List<Object> clientAssertion = httpEntityBody.get("client_assertion");
        assertThat(clientAssertion).isNotNull().isNotEmpty();
        JWTClaimsSet jwtClaimsSet = JWTParser.parse((String) clientAssertion.getFirst()).getJWTClaimsSet();
        assertThat(jwtClaimsSet.getAudience()).isEqualTo(Collections.singletonList("http://localhost:8080/uaa/oauth/token"));
        assertThat(jwtClaimsSet.getSubject()).isEqualTo("identity");
        assertThat(jwtClaimsSet.getIssuer()).isEqualTo("identity");
    }

    @Test
    void oidcJwtBearerProviderProxyThrowException() throws JOSEException, MalformedURLException {
        // Given
        KeyInfoService keyInfoService = mockKeyInfoService();
        UaaAuthenticationDetails uaaAuthenticationDetails = mock(UaaAuthenticationDetails.class);
        IdentityProvider<OIDCIdentityProviderDefinition> identityProvider = mockOidcIdentityProvider();
        /* HTTP mock */
        RestTemplate rt = mock(RestTemplate.class);
        OIDCIdentityProviderDefinition config = identityProvider.getConfig();
        when(config.getRelyingPartySecret()).thenReturn("secret");
        doReturn(false).when(config).isClientAuthInBody();
        when(rt.exchange(eq("http://localhost:8080/uaa/oauth/token"), eq(HttpMethod.POST), any(HttpEntity.class), any(ParameterizedTypeReference.class))).thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED));
        authManager = new ExternalOAuthAuthenticationManager(identityProviderProvisioning, new IdentityZoneManagerImpl(), rt, rt, tokenEndpointBuilder, keyInfoService, oidcMetadataFetcher);

        // When
        assertThatThrownBy(() -> authManager.oidcJwtBearerGrant(uaaAuthenticationDetails, identityProvider, "proxy-token"))
                .isInstanceOf(BadCredentialsException.class);
        ArgumentCaptor<HttpEntity> httpEntityArgumentCaptor = ArgumentCaptor.forClass(HttpEntity.class);

        // Then
        verify(rt, times(1)).exchange(eq("http://localhost:8080/uaa/oauth/token"), eq(HttpMethod.POST), httpEntityArgumentCaptor.capture(), eq(new ParameterizedTypeReference<Map<String, String>>() {
        }));
        HttpEntity httpEntity = httpEntityArgumentCaptor.getValue();
        HttpHeaders httpHeaders = httpEntity.getHeaders();
        assertThat(httpHeaders).containsKey("Authorization")
                .containsEntry("Authorization", Collections.singletonList("Basic aWRlbnRpdHk6c2VjcmV0"))
                .containsKey("Accept")
                .containsEntry("Content-Type", Collections.singletonList("application/x-www-form-urlencoded"));
    }

    @Test
    void oidcPasswordGrantWithForwardHeader() throws JOSEException, MalformedURLException {
        IdentityProvider<OIDCIdentityProviderDefinition> identityProvider = mockOidcIdentityProvider();
        OIDCIdentityProviderDefinition config = identityProvider.getConfig();
        KeyInfoService keyInfoService = mockKeyInfoService();
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("marissa");
        when(auth.getCredentials()).thenReturn("koala");
        UaaAuthenticationDetails details = mock(UaaAuthenticationDetails.class);
        when(details.getOrigin()).thenReturn("203.0.113.1");
        when(auth.getDetails()).thenReturn(details);

        RestTemplate rt = mock(RestTemplate.class);
        authManager = new ExternalOAuthAuthenticationManager(identityProviderProvisioning, new IdentityZoneManagerImpl(), rt, rt, tokenEndpointBuilder, keyInfoService, oidcMetadataFetcher);

        ResponseEntity<Map<String, String>> response = mock(ResponseEntity.class);
        when(response.hasBody()).thenReturn(true);
        when(response.getBody()).thenReturn(Collections.singletonMap("id_token", "mytoken"));
        when(rt.exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(ParameterizedTypeReference.class))).thenReturn(response);
        when(config.isSetForwardHeader()).thenReturn(true);
        when(config.isClientAuthInBody()).thenReturn(false);
        when(config.getRelyingPartySecret()).thenReturn("");
        when(config.getJwtClientAuthentication()).thenReturn(null);
        when(config.getScopes()).thenReturn(null);

        MultiValueMap<String, String> additionalParameters = new LinkedMultiValueMap<>();
        additionalParameters.add("username", "marissa");
        additionalParameters.add("password", "koala");

        assertThat(authManager.oauthTokenRequest(details, identityProvider, GRANT_TYPE_PASSWORD, additionalParameters)).isEqualTo("mytoken");

        ArgumentCaptor<HttpEntity> httpEntityArgumentCaptor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(rt, times(1)).exchange(eq("http://localhost:8080/uaa/oauth/token"), eq(HttpMethod.POST), httpEntityArgumentCaptor.capture(), eq(new ParameterizedTypeReference<Map<String, String>>() {
        }));
        verify(identityProviderProvisioning, times(0)).retrieveByOrigin(any(), any());
        verify(identityProviderProvisioning, times(0)).retrieveActive(any());

        HttpEntity httpEntity = httpEntityArgumentCaptor.getValue();
        assertThat(httpEntity).isNotNull();
        assertThat(httpEntity.hasBody()).isTrue();
        assertThat(httpEntity.getBody()).isInstanceOf(MultiValueMap.class);
        MultiValueMap<String, String> body = (MultiValueMap<String, String>) httpEntity.getBody();
        assertThat(body).hasSize(4)
                .containsEntry("grant_type", Collections.singletonList("password"))
                .containsEntry("response_type", Collections.singletonList("id_token"))
                .containsEntry("username", Collections.singletonList("marissa"))
                .containsEntry("password", Collections.singletonList("koala"));

        HttpHeaders headers = httpEntity.getHeaders();
        assertThat(headers.getAccept()).isEqualTo(Collections.singletonList(MediaType.APPLICATION_JSON));
        assertThat(headers.getContentType()).isEqualTo(MediaType.APPLICATION_FORM_URLENCODED);
        assertAuthorizationHeaderIsSetAndStartsWithBasic(headers);
        assertThat(headers).containsKey("X-Forwarded-For");
        final List<String> xForwardedForHeaders = headers.get("X-Forwarded-For");
        assertThat(xForwardedForHeaders).hasSize(1);
        assertThat(xForwardedForHeaders.getFirst()).isEqualTo("203.0.113.1");
    }

    @Test
    void oidcPasswordGrant_credentialsMustBeStringButNoSecretNeeded() throws MalformedURLException, JOSEException {
        RestTemplate restTemplate = mock(RestTemplate.class);
        ResponseEntity responseEntity = mock(ResponseEntity.class);

        when(restTemplate.exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(ParameterizedTypeReference.class))).thenReturn(responseEntity);
        when(responseEntity.hasBody()).thenReturn(true);
        when(responseEntity.getBody()).thenReturn(Map.of("id_token", "dummy"));
        authManager = new ExternalOAuthAuthenticationManager(identityProviderProvisioning, new IdentityZoneManagerImpl(), restTemplate, restTemplate, tokenEndpointBuilder, mockKeyInfoService(), oidcMetadataFetcher);

        final IdentityProvider<OIDCIdentityProviderDefinition> localIdp = new IdentityProvider<>();
        localIdp.setOriginKey(new AlphanumericRandomValueStringGenerator(8).generate().toLowerCase());
        final OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition()
                .setRelyingPartyId("client-id")
                .setTokenUrl(URI.create("http://localhost:8080/uaa/oauth/token").toURL());
        config.setAuthMethod("none");
        final OIDCIdentityProviderDefinition spyConfig = spy(config);
        localIdp.setConfig(spyConfig);

        assertThat(authManager.oauthTokenRequest(null, localIdp, GRANT_TYPE_PASSWORD, new LinkedMaskingMultiValueMap<>())).isEqualTo("dummy");
        verify(spyConfig, atLeast(2)).getAuthMethod();
    }

    @Test
    void oidcPasswordGrantWithPrompts() throws MalformedURLException, JOSEException {
        KeyInfoService keyInfoService = mockKeyInfoService();
        IdentityProvider<OIDCIdentityProviderDefinition> identityProvider = mockOidcIdentityProvider();
        OIDCIdentityProviderDefinition config = identityProvider.getConfig();
        UaaLoginHint loginHint = mock(UaaLoginHint.class);
        when(loginHint.getOrigin()).thenReturn("oidcprovider");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn("marissa");
        when(auth.getCredentials()).thenReturn("koala");
        UaaAuthenticationDetails uaaAuthDetails = mock(UaaAuthenticationDetails.class);
        Map<String, String[]> params = new HashMap<>();
        params.put("multivalue", new String[]{"123456", "654321"});
        params.put("emptyvalue", new String[0]);
        params.put("emptystring", new String[]{""});
        params.put("junk", new String[]{"true"});
        params.put("addcode", new String[]{"1972"});
        when(uaaAuthDetails.getParameterMap()).thenReturn(params);
        when(auth.getDetails()).thenReturn(uaaAuthDetails);

        List<Prompt> prompts = new ArrayList<>();
        prompts.add(new Prompt("username", "text", "Email"));
        prompts.add(new Prompt("password", "password", "Password"));
        prompts.add(new Prompt("passcode", "password", "Temporary Authentication Code"));
        prompts.add(new Prompt("multivalue", "password", "TOTP-Code"));
        prompts.add(new Prompt("emptyvalue", "password", "TOTP-Code"));
        prompts.add(new Prompt("emptystring", "password", "TOTP-Code"));
        prompts.add(new Prompt("missingvalue", "password", "TOTP-Code"));
        prompts.add(new Prompt("addcode", "password", "TOTP-Code"));
        when(config.getPrompts()).thenReturn(prompts);
        when(config.isSetForwardHeader()).thenReturn(false);
        when(config.isClientAuthInBody()).thenReturn(false);
        when(config.getRelyingPartySecret()).thenReturn("");
        when(config.getJwtClientAuthentication()).thenReturn(null);
        when(config.getScopes()).thenReturn(null);

        RestTemplate rt = mock(RestTemplate.class);
        authManager = new ExternalOAuthAuthenticationManager(identityProviderProvisioning, new IdentityZoneManagerImpl(), rt, rt, tokenEndpointBuilder, keyInfoService, oidcMetadataFetcher);

        ResponseEntity<Map<String, String>> response = mock(ResponseEntity.class);
        when(response.hasBody()).thenReturn(true);
        when(response.getBody()).thenReturn(Collections.singletonMap("id_token", "mytoken"));
        when(rt.exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), any(ParameterizedTypeReference.class))).thenReturn(response);

        MultiValueMap<String, String> additionalParameters = new LinkedMultiValueMap<>();
        additionalParameters.add("username", "marissa");
        additionalParameters.add("password", "koala");

        assertThat(authManager.oauthTokenRequest(uaaAuthDetails, identityProvider, GRANT_TYPE_PASSWORD, additionalParameters)).isEqualTo("mytoken");
        ArgumentCaptor<HttpEntity> httpEntityArgumentCaptor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(rt, times(1)).exchange(eq("http://localhost:8080/uaa/oauth/token"), eq(HttpMethod.POST), httpEntityArgumentCaptor.capture(), eq(new ParameterizedTypeReference<Map<String, String>>() {
        }));
        verify(identityProviderProvisioning, times(0)).retrieveByOrigin(any(), any());
        verify(identityProviderProvisioning, times(0)).retrieveActive(any());

        HttpEntity httpEntity = httpEntityArgumentCaptor.getValue();
        assertThat(httpEntity).isNotNull();
        assertThat(httpEntity.hasBody()).isTrue();
        assertThat(httpEntity.getBody()).isInstanceOf(MultiValueMap.class);
        MultiValueMap<String, String> body = (MultiValueMap<String, String>) httpEntity.getBody();
        assertThat(body).hasSize(5)
                .containsEntry("grant_type", Collections.singletonList("password"))
                .containsEntry("response_type", Collections.singletonList("id_token"))
                .containsEntry("username", Collections.singletonList("marissa"))
                .containsEntry("password", Collections.singletonList("koala"))
                .containsEntry("addcode", Collections.singletonList("1972"))
                .doesNotContainKey("passcode")
                .doesNotContainKey("multivalue")
                .doesNotContainKey("emptyvalue")
                .doesNotContainKey("emptystring")
                .doesNotContainKey("missingvalue");

        HttpHeaders headers = httpEntity.getHeaders();
        assertThat(headers.getAccept()).isEqualTo(Collections.singletonList(MediaType.APPLICATION_JSON));
        assertThat(headers.getContentType()).isEqualTo(MediaType.APPLICATION_FORM_URLENCODED);
        assertAuthorizationHeaderIsSetAndStartsWithBasic(headers);
        assertThat(headers).doesNotContainKey("X-Forwarded-For");
    }

    private static void assertAuthorizationHeaderIsSetAndStartsWithBasic(final HttpHeaders headers) {
        assertThat(headers).containsKey("Authorization");
        final List<String> authorizationHeaders = headers.get("Authorization");
        assertThat(authorizationHeaders).hasSize(1);
        assertThat(authorizationHeaders.getFirst()).startsWith("Basic ");
    }
}
