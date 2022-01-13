package org.cloudfoundry.identity.uaa.provider.oauth;

import com.google.common.testing.FakeTicker;
import org.cloudfoundry.identity.uaa.cache.StaleUrlCache;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.Signer;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.ALG;
import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.*;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.entry;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.map;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayContainingInAnyOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ExternalOAuthAuthenticationManagerTest {

    private ExternalOAuthAuthenticationManager authManager;
    private String origin;
    private String zoneId;

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    private String uaaIdentityZoneTokenSigningKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICXgIBAAKBgQDR94jLH/fHUjdMzFCajcD8E/RUWcSOPPj5mSnIM1427q0hScP9\n" +
            "yw5kifK4unqi/urO6t4IPXVN304tm8E0Um/nw3t4NAxd7aCwc0fu6wnXIlb+aZeP\n" +
            "TW14Qo8FlYqyMGu1XhKIHplPzTbSEeZsxv9cSfJHPwxhaLsiGKYRfslO4QIDAQAB\n" +
            "AoGBALafYGGcOn0pK2QmyWzEIrid+oNrWKSGr98YstiopSeOTROI/2k9NhWITo8R\n" +
            "0xz2L/EtI1VzbxX+RhcxQ8hoc19EaqQwVY01ZoN00uvYPrtoWLYKSZ9dXGReRVEH\n" +
            "fNUHfOdFKj3iVy8yat7LPHr4cX9tYWiCxaXFNB2NnUY/p9uBAkEA8Wk0MqH8hnFn\n" +
            "Zd8P6sA/k3uxDvClvfyh9V8CizNXVb+dTrDOnl3KEwhqYTkX413VCkiFsrHElMbL\n" +
            "1i7NRPhWeQJBAN6n3pVzjaUSqhbkog1TstBhfl17nrd5qvNisTftHJ/d0NKJ9buH\n" +
            "Hj7tk1MtHp1sqPa01yrevMqj9htmGi0fwakCQQDoHCLX2++UxEyKIiKHrzhxcSgY\n" +
            "GUECnniKF0O22zJJe+af1leS5NJ54kmGGQLi1UEUlg4Wdd1wvoMV+AHdInjhAkBR\n" +
            "/xJKiZaFTx1Sdvpy2/sDIJRPywHFYcoh/Zt0FB8xhJetoV7co8Lwu79Ap2IZ6XVD\n" +
            "/Y8r24E9QyqUJoLHUWWZAkEAggmAJAhcJnytfBUUCyjjc36x7wn5LzaRqp77QQCa\n" +
            "rHnyY28TwVjI/PpZgWXNdOeD4MrQuyjvr+n+5d7CCU8tYQ==\n" +
            "-----END RSA PRIVATE KEY-----";

    private String oidcProviderTokenSigningKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICXQIBAAKBgQC7FTvb+tIJN91iu2CFWXR9xCfPyyqalhCA5glhPdYNRbOPSE66\n" +
            "uLLIiovjhe+QOc9mMalK+pGc5FXRo1MECy38/mfVeOGiHtqcGfO6cxJ4B3IapQM2\n" +
            "wATWF8f6CtZqCgnXDK/noQHVcegDEf+FYrH1Tq7SWaYtE5gNmY7U7tVTwQIDAQAB\n" +
            "AoGAc57Y4sgtvKK5AMbbDS7O7tcm36YpS2aJBpCkpWNpAcTdByVh+sYhQA1YDSJ+\n" +
            "fv0rb3YrsXoQOg1n+Gre6HXcUht9pDAWeFQGLRDojV+FoiSeg4hULEve++pEdSBz\n" +
            "K8wWyP0xgdkPJYvKWsp97ehKMn9gj1esIY/hYtm5KKjb6EECQQDfRNFHaMHr7avR\n" +
            "x9Hv9lPm6Q4TSQDQCkk+LRXry8vyGicGXxdDMbq2HM6IcykD2dWDdDyrN4H8eh6d\n" +
            "Bpvpv2kpAkEA1oJgR1MJ3FTL+4581DiawvsvH+Cy3le6iHwyN9qclM0ABgwNgFKu\n" +
            "upssAwsHH88cy1ed2jLrQZJ6s2qSHSGw2QJBALBm6wMEndMOYabJvfFeKkRS9q/+\n" +
            "CgpVVjEt5hf7WRPb3eGG2BZbAC5K7FOayVkljzDhcd3FaYpV4kImqqEwfqECQGNV\n" +
            "2toMtTtINXIXyOzKDbkPcwIzHwHh5GrCAMtmvC4YRNOID1SGdY3Kv/XkzHbJhY8Q\n" +
            "0vOxssoZ2CJvzpwY9vkCQQCS/iledrtBdaAk/lwphZUZcSh/qDn6on5sZnf+3DgZ\n" +
            "PEw0pNKKUspeBvWwNMltYeRMw032ovZAmZewYQAqOB+a\n" +
            "-----END RSA PRIVATE KEY-----";

    private String changedOidcProviderTokenSigningKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICWwIBAAKBgQC1jt6DNm92RxO2/ZD2/QgPYTHmMk9FvCUTbBkIL4TQDDFwcuDn\n" +
            "Qz8ZbotvhNFwQe2vnHa641u9jEdm7xlL6U6WCNdJcoGIK274gFy82G7h7QcKxoJm\n" +
            "Dbu7G1c6NrX7EMxr2jhClRSji4w5JgI0tfSD2Q8onkr1xKOzqIFundRptQIDAQAB\n" +
            "AoGBALK5W22LLpoeSdf/MK8SUtbg9QAIUmTxWwYNiW63aGRtPFXXoHHHjtv4KCa1\n" +
            "dn6tR89xlKdQnMSwzLEVea9ykboRc3bSV8sSgJq4nOHWrgmf5UCSopyZ2no70g+a\n" +
            "E0j/vD7S/wqSai8L/Drv/9Jwm836b9DZVk9+2wiGQkgXMTLBAkEA7uqCpyxR0SNb\n" +
            "wV3SnuPoN23Yn6AWCDJSm/APGz026eFk0UJmPn4SzDpJ2RTyjmglKCjVhW94VGdk\n" +
            "qNEfPRQ9yQJBAMKKY74XvYenAmWWYG/oIUuzju1fiLFQF5gfj9FkIrdqpfYvCQWE\n" +
            "J8oj2mlNyRG4/j+kYpF31L+guoOeMLDEUo0CQCLjN8T1odTqVuG7s5/kI+rELZfR\n" +
            "pqX3wzxmJ66Ql847TZ+JFKkXe+M6t8HtXyYQayycGeHsTyP0HSzRrMAcjpECQEfH\n" +
            "chfwgIDt0UeUXY7M0oQxA1p4NmJeD+aUNqdm0Bxm4EdegXCkm13NLshN6BN+82ie\n" +
            "CbRsx3XRIyBvHL4MIf0CPzNQw6BchRE49seUppUuM4d4sLSvCpzursd7i5BzUXLO\n" +
            "37Pnjj5qtLTqL44gMQbAfl0WyeztQn81GgzpaKRfVA==\n" +
            "-----END RSA PRIVATE KEY-----";

    private OIDCIdentityProviderDefinition oidcConfig;
    private String uaaIssuerBaseUrl;
    private TokenEndpointBuilder tokenEndpointBuilder;
    private IdentityProvider provider;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private JdbcScimGroupExternalMembershipManager externalMembershipManager;

    @Before
    public void setup() throws Exception {
        origin = "google-oidc";
        zoneId = "zoneId";
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(zoneId);
        IdentityZoneHolder.set(identityZone);

        identityProviderProvisioning = mock(IdentityProviderProvisioning.class);
        externalMembershipManager = mock(JdbcScimGroupExternalMembershipManager.class);
        provider = new IdentityProvider();
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
            new StaleUrlCache(Duration.ofMinutes(2), new TimeServiceImpl(), 10, new FakeTicker()),
            new RestTemplate(),
            new RestTemplate()
        );
        authManager = new ExternalOAuthAuthenticationManager(identityProviderProvisioning, new RestTemplate(), new RestTemplate(), tokenEndpointBuilder, new KeyInfoService(uaaIssuerBaseUrl), oidcMetadataFetcher);
        authManager.setExternalMembershipManager(externalMembershipManager);
    }

    @After
    public void cleanup() {
        IdentityZoneHolder.clear();
    }

    @Test
    public void getExternalAuthenticationDetails_whenProviderHasSigningKey_throwsWhenIdTokenCannotBeValidated() {
        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("Could not verify token signature.");

        Map<String, Object> header = map(
                entry(ALG, "HS256"),
                entry(KID, "oidc-provider-key")
        );
        Signer signer = new RsaSigner(changedOidcProviderTokenSigningKey);
        Map<String, Object> claims = map(
                entry(EMAIL, "someuser@google.com")
        );
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", uaaIdentityZoneTokenSigningKey));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken("thecode", origin, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
        authManager.getExternalAuthenticationDetails(oidcAuthentication);
    }

    @Test
    public void getExternalAuthenticationDetails_whenProviderIssuerMatchesUaaIssuer_throwsWhenIdTokenCannotBeValidated() {
        oidcConfig.setIssuer(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()));
        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("Could not verify token signature.");

        Map<String, Object> header = map(
                entry(ALG, "HS256"),
                entry(KID, "uaa-key")
        );
        Signer signer = new RsaSigner(oidcProviderTokenSigningKey);
        Map<String, Object> claims = map(
                entry(EMAIL, "someuser@google.com")
        );
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", uaaIdentityZoneTokenSigningKey));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken(null, origin, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
        authManager.getExternalAuthenticationDetails(oidcAuthentication);
    }

    @Test
    public void getExternalAuthenticationDetails_doesNotThrowWhenIdTokenIsValid() {
        Map<String, Object> header = map(
                entry(ALG, "HS256"),
                entry(KID, "oidc-provider-key")
        );
        Signer signer = new RsaSigner(oidcProviderTokenSigningKey);
        Map<String, Object> claims = map(
                entry(EMAIL, "someuser@google.com"),
                entry(ISS, oidcConfig.getIssuer()),
                entry(AUD, "uaa-relying-party"),
                entry(EXPIRY_IN_SECONDS, ((int) (System.currentTimeMillis()/1000L)) + 60),
                entry(SUB, "abc-def-asdf")
        );
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", uaaIdentityZoneTokenSigningKey));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken(null, origin, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
        authManager.getExternalAuthenticationDetails(oidcAuthentication);
        // no exception expected
    }

    @Test
    public void getExternalAuthenticationDetails_whenUaaToken_doesNotThrowWhenIdTokenIsValid() {
        oidcConfig.setIssuer(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()));
        Map<String, Object> header = map(
                entry(ALG, "HS256"),
                entry(KID, "uaa-key")
        );
        Signer signer = new RsaSigner(uaaIdentityZoneTokenSigningKey);
        Map<String, Object> claims = map(
                entry(EMAIL, "someuser@google.com"),
                entry(ISS, oidcConfig.getIssuer()),
                entry(AUD, "uaa-relying-party"),
                entry(EXPIRY_IN_SECONDS, ((int) (System.currentTimeMillis()/1000L)) + 60),
                entry(SUB, "abc-def-asdf")
        );
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(Collections.singletonMap("uaa-key", uaaIdentityZoneTokenSigningKey));
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);

        ExternalOAuthCodeToken oidcAuthentication = new ExternalOAuthCodeToken("thecode", origin, "http://google.com", idTokenJwt, "accesstoken", "signedrequest");
        authManager.getExternalAuthenticationDetails(oidcAuthentication);
        // no exception expected
    }

    @Test
    public void getExternalAuthenticationDetails_whenUaaToken_mapRoleAsExplicitToScopeWhenIdTokenIsValid() {
        oidcConfig.setIssuer(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()));
        Map<String, Object> header = map(
            entry(ALG, "HS256"),
            entry(KID, "uaa-key")
        );
        Signer signer = new RsaSigner(uaaIdentityZoneTokenSigningKey);
        List<String> roles = Arrays.asList("manager.us", "manager.eu");
        Map<String, Object> claims = map(
            entry(EMAIL, "someuser@google.com"),
            entry(ISS, oidcConfig.getIssuer()),
            entry(AUD, "uaa-relying-party"),
            entry(ROLES, roles),
            entry(EXPIRY_IN_SECONDS, ((int) (System.currentTimeMillis()/1000L)) + 60),
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
        assertNotNull(authenticationData);
        assertEquals(0, authenticationData.getAuthorities().size());
        // no exception expected
    }

    @Test
    public void getExternalAuthenticationDetails_whenUaaToken_mapRoleAsScopeToScopeWhenIdTokenIsValid() {
        oidcConfig.setIssuer(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()));
        Map<String, Object> header = map(
            entry(ALG, "HS256"),
            entry(KID, "uaa-key")
        );
        Signer signer = new RsaSigner(uaaIdentityZoneTokenSigningKey);
        Set<String> roles = new HashSet<>(Arrays.asList("manager.us", "manager.eu"));
        Map<String, Object> claims = map(
            entry(EMAIL, "someuser@google.com"),
            entry(ISS, oidcConfig.getIssuer()),
            entry(AUD, "uaa-relying-party"),
            entry(ROLES, roles),
            entry(EXPIRY_IN_SECONDS, ((int) (System.currentTimeMillis()/1000L)) + 60),
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
        assertNotNull(authenticationData);
        assertEquals(2, authenticationData.getAuthorities().size());
        Set<String> authicatedAuthorities = AuthorityUtils.authorityListToSet(authenticationData.getAuthorities());
        assertThat(roles.toArray(), arrayContainingInAnyOrder(authicatedAuthorities.toArray()));
        // no exception expected, but same array content in authority list
    }
}