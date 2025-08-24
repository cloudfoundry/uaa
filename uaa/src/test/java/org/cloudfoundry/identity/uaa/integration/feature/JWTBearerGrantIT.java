package org.cloudfoundry.identity.uaa.integration.feature;

import com.nimbusds.jwt.JWTClaimsSet;
import org.cloudfoundry.identity.uaa.ServerRunningExtension;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.client.test.TestAccounts;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.web.client.RestTemplate;

import java.net.Inet4Address;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
class JWTBearerGrantIT {
    /**
     *  Test Scenario for https://github.com/cloudfoundry/community/blob/main/toc/rfc/rfc-0037-deprecate-passwords.md#extension
     *
     *  Setup: 3 Zones UAA, testzone3, testzone4 using OIDC identity provider proxies to do principal propagation from
     *  one zone to the other.
     *
     */

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Autowired
    TestAccounts testAccounts;

    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    private RestTemplate identityClient;
    private IdentityZone testzone3;
    private IdentityZone testzone4;

    private static boolean doesSupportZoneDNS() {
        try {
            return Arrays.equals(Inet4Address.getByName("testzone3.localhost").getAddress(), new byte[]{127, 0, 0, 1});
        } catch (UnknownHostException e) {
            return false;
        }
    }

    @BeforeEach
    @AfterEach
    void logout_and_clear_cookies() {
        assertThat(doesSupportZoneDNS()).as("/etc/hosts should contain the host 'testzone3/4.localhost' for this test to work").isTrue();
        try {
            webDriver.get(baseUrl + "/logout.do");
        } catch (org.openqa.selenium.TimeoutException x) {
            //try again - this should not be happening - 20 second timeouts
            webDriver.get(baseUrl + "/logout.do");
        }
        webDriver.manage().deleteAllCookies();
    }

    private String getIdTokenUaaZone() {
        return (String) IntegrationTestUtils.getPasswordToken(baseUrl, "cf", "", testAccounts.getUserName(),
                testAccounts.getPassword(), null).get("id_token");
    }

    private String getJwtBearerResult(String idToken) {
        return (String) IntegrationTestUtils.getJwtBearerToken(baseUrl, "cf", "", idToken,
                null, null).get("id_token");
    }

    private String getJwtBearerResult(String idToken, String zoneUrl, String origin) {
        return (String) IntegrationTestUtils.getJwtBearerToken(zoneUrl, "cf", "", idToken,
                origin, null).get("id_token");
    }

    private String getZoneUrl(IdentityZone idz) {
        return idz == null || ObjectUtils.isEmpty(idz.getSubdomain()) || UAA.equals(idz.getSubdomain()) ?
                baseUrl : baseUrl.replace("localhost", idz.getSubdomain() + ".localhost");
    }

    private static Map<String, Object> getClaimMap(String idToken)  {
        assertThat(idToken).isNotNull();
        return UaaTokenUtils.getClaims(idToken, Map.class);
    }

    private static JWTClaimsSet getClaimSet(String idToken)  {
        assertThat(idToken).isNotNull();
        return JwtHelper.decode(idToken).getClaimSet();
    }

    private IdentityZone createIdentityZone(String subdomain, String originKey) {
        IdentityZone zone = IdentityZone.getUaa();
        zone.setSubdomain(subdomain);
        zone.setId(subdomain);
        zone.setCreated(new Date());
        zone.setLastModified(new Date());
        zone.setDescription("test zone " + subdomain);
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setDefaultIdentityProvider(originKey);
        config.setAccountChooserEnabled(true);
        config.setIdpDiscoveryEnabled(false);
        zone.setConfig(config);
        return zone;
    }

    private IdentityZone saveIdentityZone(IdentityZone identityZone) {
        identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
        //create the zone
        return IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl,  identityZone.getId(), identityZone.getSubdomain(), identityZone.getConfig());
    }

    private String createCfClientReturnAdminToken(IdentityZone identityZone) {
        String zoneAdminToken = IntegrationTestUtils.getZoneAdminToken(baseUrl, serverRunning, identityZone.getId());
        // create standard cf client in the zone
        createCfClientInZone(zoneAdminToken, identityZone.getId());
        return zoneAdminToken;
    }

    private void createOidcProvider(String clientCredentialsToken, String trustedZoneDomain, String originKey, String zoneId) throws MalformedURLException {
        IdentityProvider identityProvider = new IdentityProvider<>();
        identityProvider.setName("my oidc provider");
        identityProvider.setIdentityZoneId(zoneId);
        OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition();
        config.setClientAuthInBody(false);
        config.addAttributeMapping(USER_NAME_ATTRIBUTE_NAME, "user_name");
        config.addAttributeMapping("given_name", "email");
        config.addAttributeMapping("family_name", "email");
        config.addAttributeMapping("user.attribute." + "the_client_id", "cid");
        config.addAttributeMapping("external_groups", "scope");
        config.setStoreCustomAttributes(true);
        config.addWhiteListedGroup("*");
        config.setAuthUrl(new URL(trustedZoneDomain + "/oauth/authorize"));
        config.setTokenUrl(new URL(trustedZoneDomain + "/oauth/token"));
        config.setTokenKeyUrl(new URL(trustedZoneDomain + "/token_key"));
        config.setIssuer(trustedZoneDomain + "/oauth/token");
        config.setUserInfoUrl(new URL(trustedZoneDomain + "/userinfo"));
        config.setShowLinkText(true);
        config.setLinkText("My OIDC Provider");
        config.setSkipSslValidation(true);
        config.setRelyingPartyId("cf");
        config.setRelyingPartySecret("");
        // no password forward
        config.setPasswordGrantEnabled(false);
        // jwt bearer forward
        config.setTokenExchangeEnabled(true);
        identityProvider.setConfig(config);
        identityProvider.setOriginKey(originKey);
        IntegrationTestUtils.createOrUpdateProvider(clientCredentialsToken, baseUrl, identityProvider);
    }

    private void createCfClientInZone(String adminToken, String zoneId) {
        String clientId = "cf";
        UaaClientDetails client = new UaaClientDetails(clientId, null, "openid", GRANT_TYPE_JWT_BEARER, "openid", null);
        client.setClientSecret("");
        client.setAutoApproveScopes(Collections.singletonList("true"));
        IntegrationTestUtils.createOrUpdateClient(adminToken, baseUrl, zoneId, client);
    }

    private void validateJwtClaimMap(String token, String grantType, String originKey) {
        Map<String, Object> claims = getClaimMap(token);
        assertThat(claims)
                .containsEntry("client_id", "cf")
                .containsEntry("cid", "cf")
                .containsEntry("origin", originKey)
                .containsEntry("grant_type", grantType)
                .containsEntry("user_name", testAccounts.getUserName());
    }

    private void validateJwtClaimSet(String token, String grantType, IdentityZone zone, String originKey) throws Exception {
        JWTClaimsSet resultToken = getClaimSet(token);
        assertThat(resultToken.getExpirationTime()).isAfter(Instant.now()).as("check exp claim");
        assertThat(resultToken.getIssueTime()).isBefore(Instant.now()).as("check iat claim");
        assertThat(resultToken.getIssuer()).isEqualTo(UaaTokenUtils.constructTokenEndpointUrl(baseUrl, zone));
        assertThat(resultToken.getSubject()).isNotNull().as("check subject claim exists only");
        assertThat(resultToken.getAudience()).contains("cf").as("check aud claim");
        assertThat(resultToken.getStringClaim("zid")).isEqualTo(zone.getId()).as("check zid claim");
        assertThat(resultToken.getStringClaim("client_id")).isEqualTo("cf").as("check client_id claim");
        assertThat(resultToken.getStringClaim("cid")).isEqualTo("cf").as("check cid claim");
        assertThat(resultToken.getStringClaim("origin")).isEqualTo(originKey).as("check origin claim");
        assertThat(resultToken.getStringClaim("user_name")).isEqualTo(testAccounts.getUserName()).as("check user_name claim");
        assertThat(resultToken.getStringClaim("email")).startsWith(testAccounts.getUserName()).as("check email partly");
        assertThat(resultToken.getStringClaim("grant_type")).isEqualTo(grantType).as("check grant_type claim");
    }

    /**
     * JWT bearer within the same zone without extra IdP setup
     *
     * @throws Exception
     */
    @Test
    void simpleLoginWithJwtBearerTokenSameZone() throws Exception {
        // Given
        String passwordToken = getIdTokenUaaZone();
        // When
        String jwtBearerToken = getJwtBearerResult(passwordToken);
        // Then
        validateJwtClaimSet(passwordToken, GRANT_TYPE_PASSWORD, IdentityZone.getUaa(), "uaa");
        Map<String, Object> claims = UaaTokenUtils.getClaims(jwtBearerToken, Map.class);
        assertThat(claims).containsEntry("origin", "uaa")
                .containsEntry("client_id", "cf")
                .containsEntry("cid", "cf")
                .containsEntry("user_name", testAccounts.getUserName());
        validateJwtClaimSet(jwtBearerToken, GRANT_TYPE_JWT_BEARER, IdentityZone.getUaa(), "uaa"/* means no idp */);
    }

    /**
     * Test should support login from UAA to testzone3
     * Trust is: testzone3 -> uaa
     *
     * @throws Exception
     */
    @Test
    void userLoginViaBearerGrantOidcZone() throws Exception {
        String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");
        String testZone3Domain = "testzone3";
        String originInZone3 = "uaa-zone-ipd-proxy";

        try {
            // Given
            testzone3 = saveIdentityZone(createIdentityZone(testZone3Domain, originInZone3));
            String zoneAdminToken = createCfClientReturnAdminToken(testzone3);
            createOidcProvider(zoneAdminToken, getZoneUrl(IdentityZone.getUaa()), originInZone3, testzone3.getId());
            // When - get id token from password grant
            String tokenInZoneUaa = getIdTokenUaaZone();
            // Then
            validateJwtClaimMap(tokenInZoneUaa, GRANT_TYPE_PASSWORD, "uaa");
            // When
            String jwtBearer = getJwtBearerResult(tokenInZoneUaa, getZoneUrl(testzone3), null);
            // Then
            validateJwtClaimMap(jwtBearer, GRANT_TYPE_JWT_BEARER, originInZone3);
            // JwtClaimSet ensure that id token is valid also with another OS library
            validateJwtClaimSet(jwtBearer, GRANT_TYPE_JWT_BEARER, testzone3, originInZone3);
        } finally {
            if (testzone3 != null) {
                IntegrationTestUtils.deleteZone(baseUrl, testzone3.getId(), clientCredentialsToken);
            }
        }
    }

    /**
     * Test should support login from UAA to testzone4, but testzone4 has no direct trust to uaa zone.
     * Trust is: testzone4 -> testzone3 -> uaa
     *
     * @throws Exception
     */
    @Test
    void userLoginViaTransientBearerGrantOidcZone() throws Exception {
        String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");
        String testZone3Domain = "testzone3";
        String originInZone3 = "uaa-zone-ipd-proxy";
        String testZone4Domain = "testzone4";
        String originInZone4 = "testzone3-zone-ipd-proxy";

        try {
            // Given testzone3 setup
            testzone3 = saveIdentityZone(createIdentityZone(testZone3Domain, originInZone3));
            String zone3AdminToken = createCfClientReturnAdminToken(testzone3);
            createOidcProvider(zone3AdminToken, getZoneUrl(IdentityZone.getUaa()), originInZone3, testzone3.getId());
            // Given testzone4 setup
            testzone4 = saveIdentityZone(createIdentityZone(testZone4Domain, originInZone4));
            String zone4AdminToken = createCfClientReturnAdminToken(testzone4);
            createOidcProvider(zone4AdminToken, getZoneUrl(testzone3), originInZone4, testzone4.getId());
            // When - get id token from password grant
            String tokenInZoneUaa = getIdTokenUaaZone();
            // Then
            validateJwtClaimMap(tokenInZoneUaa, GRANT_TYPE_PASSWORD, "uaa");
            // When - get id token from jwt trusting uaa zone to testzone4 with testzone3 in between as proxy or transient trust
            String jwtBearer = getJwtBearerResult(tokenInZoneUaa, getZoneUrl(testzone4), originInZone4);
            // Then
            validateJwtClaimMap(jwtBearer, GRANT_TYPE_JWT_BEARER, originInZone4);
            // JwtClaimSet ensure that id token is valid also with another OS library
            validateJwtClaimSet(jwtBearer, GRANT_TYPE_JWT_BEARER, testzone4, originInZone4);
        } finally {
            if (testzone3 != null) {
                IntegrationTestUtils.deleteZone(baseUrl, testzone3.getId(), clientCredentialsToken);
            }
            if (testzone4 != null) {
                IntegrationTestUtils.deleteZone(baseUrl, testzone4.getId(), clientCredentialsToken);
            }
        }
    }
}
