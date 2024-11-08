package org.cloudfoundry.identity.uaa.provider.oauth;

import com.github.benmanes.caffeine.cache.Ticker;
import com.nimbusds.jose.HeaderParameterNames;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.cache.StaleUrlCache;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AUD;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EMAIL;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EXPIRY_IN_SECONDS;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ISS;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ROLES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SUB;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.FAMILY_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.entry;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.map;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.DEFAULT_UAA_URL;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ExternalOAuthAuthenticationManagerTest {
    private static final String OIDC_PROVIDER_KEY = "oidc-provider-key";
    private ExternalOAuthAuthenticationManager authManager;
    private String origin;
    private String zoneId;

    private final String uaaIdentityZoneTokenSigningKey = """
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

    private final String oidcProviderTokenSigningKey = """
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

    private OIDCIdentityProviderDefinition oidcConfig;
    private String uaaIssuerBaseUrl;
    private TokenEndpointBuilder tokenEndpointBuilder;
    private IdentityProvider<OIDCIdentityProviderDefinition> provider;
    private IdentityProviderProvisioning identityProviderProvisioning;

    @BeforeEach
    public void beforeEach() throws Exception {
        origin = "google-oidc";
        zoneId = "zoneId";
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(zoneId);
        IdentityZoneHolder.set(identityZone);

        identityProviderProvisioning = mock(IdentityProviderProvisioning.class);
        JdbcScimGroupExternalMembershipManager externalMembershipManager = mock(JdbcScimGroupExternalMembershipManager.class);
        provider = new IdentityProvider<>();
        oidcConfig = new OIDCIdentityProviderDefinition();
        String oidcIssuerUrl = "http://issuer.com";
        oidcConfig.setIssuer(oidcIssuerUrl);
        oidcConfig.setTokenKey(oidcProviderTokenSigningKey);
        oidcConfig.setRelyingPartyId("uaa-relying-party");
        Map<String, Object> externalGroupMapping = map(
                entry(GROUP_ATTRIBUTE_NAME, "roles")
        );
        oidcConfig.setAttributeMappings(externalGroupMapping);
        provider.setConfig(oidcConfig);
        when(identityProviderProvisioning.retrieveByOrigin(origin, zoneId)).thenReturn(provider);
        uaaIssuerBaseUrl = "http://uaa.example.com";
        tokenEndpointBuilder = new TokenEndpointBuilder(uaaIssuerBaseUrl);
        OidcMetadataFetcher oidcMetadataFetcher = new OidcMetadataFetcher(
                new StaleUrlCache(Duration.ofMinutes(2), new TimeServiceImpl(), 10, Ticker.disabledTicker()),
                new RestTemplate(),
                new RestTemplate()
        );
        authManager = new ExternalOAuthAuthenticationManager(identityProviderProvisioning, new RestTemplate(), new RestTemplate(), tokenEndpointBuilder, new KeyInfoService(uaaIssuerBaseUrl), oidcMetadataFetcher);
        authManager.setExternalMembershipManager(externalMembershipManager);
    }

    @AfterEach
    public void afterEach() {
        IdentityZoneHolder.clear();
    }

    @Test
    void getExternalAuthenticationDetails_whenProviderHasSigningKey_throwsWhenIdTokenCannotBeValidated() {
        Map<String, Object> header = map(
                entry(HeaderParameterNames.ALGORITHM, JWSAlgorithm.RS256.getName()),
                entry(HeaderParameterNames.KEY_ID, OIDC_PROVIDER_KEY)
        );
        JWSSigner signer = new KeyInfo(OIDC_PROVIDER_KEY, oidcProviderTokenSigningKey, DEFAULT_UAA_URL).getSigner();
        Map<String, Object> claims = map(
                entry(EXPIRY_IN_SECONDS, 0),
                entry(AUD, "uaa-relying-party"),
                entry(ISS, oidcConfig.getIssuer()),
                entry(EMAIL, "someuser@google.com")
        );
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", uaaIdentityZoneTokenSigningKey));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken("thecode", origin, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
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
        JWSSigner signer = new KeyInfo("uaa-key", oidcProviderTokenSigningKey, DEFAULT_UAA_URL).getSigner();
        Map<String, Object> claims = map(
                entry(EMAIL, "someuser@google.com")
        );
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", uaaIdentityZoneTokenSigningKey));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken(null, origin, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
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
        JWSSigner signer = new KeyInfo(OIDC_PROVIDER_KEY, oidcProviderTokenSigningKey, DEFAULT_UAA_URL).getSigner();
        Map<String, Object> claims = map(
                entry(EMAIL, "someuser@google.com"),
                entry(ISS, oidcConfig.getIssuer()),
                entry(AUD, "uaa-relying-party"),
                entry(EXPIRY_IN_SECONDS, ((int) (System.currentTimeMillis() / 1000L)) + 60),
                entry(SUB, "abc-def-asdf")
        );
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", uaaIdentityZoneTokenSigningKey));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken(null, origin, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
        assertThatNoException().isThrownBy(() -> authManager.getExternalAuthenticationDetails(oidcAuthentication));
    }

    @Test
    void getExternalAuthenticationDetails_whenUaaToken_doesNotThrowWhenIdTokenIsValid() {
        oidcConfig.setIssuer(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()));
        Map<String, Object> header = map(
                entry(HeaderParameterNames.ALGORITHM, JWSAlgorithm.RS256.getName()),
                entry(HeaderParameterNames.KEY_ID, "uaa-key")
        );
        JWSSigner signer = new KeyInfo("uaa-key", uaaIdentityZoneTokenSigningKey, DEFAULT_UAA_URL).getSigner();
        Map<String, Object> claims = map(
                entry(EMAIL, "someuser@google.com"),
                entry(ISS, oidcConfig.getIssuer()),
                entry(AUD, "uaa-relying-party"),
                entry(EXPIRY_IN_SECONDS, ((int) (System.currentTimeMillis() / 1000L)) + 60),
                entry(SUB, "abc-def-asdf")
        );
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", uaaIdentityZoneTokenSigningKey));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken("thecode", origin, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
        assertThatNoException().isThrownBy(() -> authManager.getExternalAuthenticationDetails(oidcAuthentication));
    }

    @Test
    void getExternalAuthenticationDetails_whenUaaToken_mapRoleAsExplicitToScopeWhenIdTokenIsValid() {
        oidcConfig.setIssuer(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()));
        Map<String, Object> header = map(
                entry(HeaderParameterNames.ALGORITHM, JWSAlgorithm.RS256.getName()),
                entry(HeaderParameterNames.KEY_ID, "uaa-key")
        );
        JWSSigner signer = new KeyInfo("uaa-key", uaaIdentityZoneTokenSigningKey, DEFAULT_UAA_URL).getSigner();
        List<String> roles = Arrays.asList("manager.us", "manager.eu");
        Map<String, Object> claims = map(
                entry(EMAIL, "someuser@google.com"),
                entry(ISS, oidcConfig.getIssuer()),
                entry(AUD, "uaa-relying-party"),
                entry(ROLES, roles),
                entry(EXPIRY_IN_SECONDS, ((int) (System.currentTimeMillis() / 1000L)) + 60),
                entry(SUB, "abc-def-asdf")
        );
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", uaaIdentityZoneTokenSigningKey));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);
        // When
        oidcConfig.setGroupMappingMode(AbstractExternalOAuthIdentityProviderDefinition.OAuthGroupMappingMode.EXPLICITLY_MAPPED);
        provider.setConfig(oidcConfig);
        when(identityProviderProvisioning.retrieveByOrigin(origin, zoneId)).thenReturn(provider);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken("thecode", origin, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
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
        JWSSigner signer = new KeyInfo("uaa-key", uaaIdentityZoneTokenSigningKey, DEFAULT_UAA_URL).getSigner();
        Set<String> roles = new HashSet<>(Arrays.asList("manager.us", "manager.eu"));
        Map<String, Object> claims = map(
                entry(EMAIL, "someuser@google.com"),
                entry(ISS, oidcConfig.getIssuer()),
                entry(AUD, "uaa-relying-party"),
                entry(ROLES, roles),
                entry(EXPIRY_IN_SECONDS, ((int) (System.currentTimeMillis() / 1000L)) + 60),
                entry(SUB, "abc-def-asdf")
        );
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", uaaIdentityZoneTokenSigningKey));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);
        // When
        oidcConfig.setGroupMappingMode(AbstractExternalOAuthIdentityProviderDefinition.OAuthGroupMappingMode.AS_SCOPES);
        provider.setConfig(oidcConfig);
        when(identityProviderProvisioning.retrieveByOrigin(origin, zoneId)).thenReturn(provider);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken("thecode", origin, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
        ExternalOAuthAuthenticationManager.AuthenticationData authenticationData = authManager.getExternalAuthenticationDetails(oidcAuthentication);
        assertThat(authenticationData).isNotNull();
        assertThat(authenticationData.getAuthorities()).hasSize(2);
        Set<String> authicatedAuthorities = AuthorityUtils.authorityListToSet(authenticationData.getAuthorities());
        assertThat(roles.toArray()).contains(authicatedAuthorities.toArray());
        // no exception expected, but same array content in authority list
    }

    @Test
    void getExternalAuthenticationDetails_whenUaaToken_mapRoleAsScopeToScopeWhenIdTokenIsValid_AndFilterManagerRolesOnly() {
        oidcConfig.setIssuer(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()));
        Map<String, Object> header = map(
                entry(HeaderParameterNames.ALGORITHM, JWSAlgorithm.RS256.getName()),
                entry(HeaderParameterNames.KEY_ID, "uaa-key")
        );
        JWSSigner signer = new KeyInfo("uaa-key", uaaIdentityZoneTokenSigningKey, DEFAULT_UAA_URL).getSigner();
        Set<String> roles = new HashSet<>(Arrays.asList("manager.us", "manager.eu", "uaa.admin", "uaa.user", "idp.write", "employee.us"));
        Map<String, Object> claims = map(
                entry(EMAIL, "someuser@google.com"),
                entry(ISS, oidcConfig.getIssuer()),
                entry(AUD, "uaa-relying-party"),
                entry(ROLES, roles),
                entry(EXPIRY_IN_SECONDS, ((int) (System.currentTimeMillis() / 1000L)) + 60),
                entry(SUB, "abc-def-asdf")
        );
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", uaaIdentityZoneTokenSigningKey));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);
        // When
        oidcConfig.setGroupMappingMode(AbstractExternalOAuthIdentityProviderDefinition.OAuthGroupMappingMode.AS_SCOPES);
        oidcConfig.setExternalGroupsWhitelist(List.of("manager.*"));
        provider.setConfig(oidcConfig);
        when(identityProviderProvisioning.retrieveByOrigin(origin, zoneId)).thenReturn(provider);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken("thecode", origin, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
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
        JWSSigner signer = new KeyInfo(OIDC_PROVIDER_KEY, oidcProviderTokenSigningKey, DEFAULT_UAA_URL).getSigner();
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
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", uaaIdentityZoneTokenSigningKey));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken(null, origin, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
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
        JWSSigner signer = new KeyInfo(OIDC_PROVIDER_KEY, oidcProviderTokenSigningKey, DEFAULT_UAA_URL).getSigner();
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
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", uaaIdentityZoneTokenSigningKey));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken(null, origin, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
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
        JWSSigner signer = new KeyInfo("uaa-key", oidcProviderTokenSigningKey, DEFAULT_UAA_URL).getSigner();
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
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", uaaIdentityZoneTokenSigningKey));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken(null, origin, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
        ExternalOAuthAuthenticationManager.AuthenticationData externalAuthenticationDetails = authManager.getExternalAuthenticationDetails(oidcAuthentication);
        assertThatThrownBy(() -> authManager.getUser(oidcAuthentication, externalAuthenticationDetails))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("External token attribute external_family_name cannot be mapped to user attribute family_name");
    }

    @Test
    void populateAuthenticationAttributes_setsIdpIdToken() {
        UaaAuthentication authentication = new UaaAuthentication(new UaaPrincipal("user-guid", "marissa", "marissa@test.org", "uaa", "", ""), Collections.emptyList(), null);
        Map<String, Object> header = map(
                entry(HeaderParameterNames.ALGORITHM, JWSAlgorithm.RS256.getName()),
                entry(HeaderParameterNames.KEY_ID, OIDC_PROVIDER_KEY)
        );
        JWSSigner signer = new KeyInfo("uaa-key", oidcProviderTokenSigningKey, DEFAULT_UAA_URL).getSigner();
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
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", uaaIdentityZoneTokenSigningKey));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);
        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken(null, origin, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
        ExternalOAuthAuthenticationManager.AuthenticationData authenticationData = authManager.getExternalAuthenticationDetails(oidcAuthentication);
        authManager.populateAuthenticationAttributes(authentication, oidcAuthentication, authenticationData);
        assertThat(authentication.getIdpIdToken()).isEqualTo(idTokenJwt);
    }

    @Test
    void getClaimsFromToken_setsIdToken() {
        Map<String, Object> header = map(
                entry(HeaderParameterNames.ALGORITHM, JWSAlgorithm.RS256.getName()),
                entry(HeaderParameterNames.KEY_ID, OIDC_PROVIDER_KEY)
        );
        JWSSigner signer = new KeyInfo("uaa-key", oidcProviderTokenSigningKey, DEFAULT_UAA_URL).getSigner();
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
        ExternalOAuthCodeToken codeToken = new ExternalOAuthCodeToken("thecode", origin, "http://google.com", null, "accesstoken", "signedrequest");

        authManager = new ExternalOAuthAuthenticationManager(identityProviderProvisioning, new RestTemplate(), new RestTemplate(), tokenEndpointBuilder, new KeyInfoService(uaaIssuerBaseUrl), null) {
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
}
