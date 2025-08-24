/*
 * *****************************************************************************
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
package org.cloudfoundry.identity.uaa.integration.feature;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.ServerRunningExtension;
import org.cloudfoundry.identity.uaa.account.UserInfoResponse;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.endpoints.SamlLogoutAuthSourceEndpoint;
import org.cloudfoundry.identity.uaa.integration.pageObjects.Page;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.integration.util.ScreenshotOnFailExtension;
import org.cloudfoundry.identity.uaa.oauth.client.test.TestAccounts;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.UaaWebDriver;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import java.net.Inet4Address;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.isMember;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SUB;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
@ExtendWith(ScreenshotOnFailExtension.class)
public class OIDCLoginIT {

    private static final String PASSWORD_AUTHN_CTX = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";

    @Autowired
    @RegisterExtension
    private IntegrationTestExtension integrationTestExtension;

    @Autowired
    UaaWebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Autowired
    TestAccounts testAccounts;

    @Autowired
    SamlServerConfig samlServerConfig;

    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    private IdentityZone zone;
    private String adminToken;
    private String subdomain;
    private String zoneUrl;
    private IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition<?>> identityProvider;
    private String clientCredentialsToken;
    private UaaClientDetails zoneClient;
    private ScimGroup createdGroup;
    private RestTemplate identityClient;

    public static boolean doesSupportZoneDNS() {
        try {
            return Arrays.equals(Inet4Address.getByName("oidcloginit.localhost").getAddress(), new byte[]{127, 0, 0, 1});
        } catch (UnknownHostException e) {
            return false;
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        assertThat(doesSupportZoneDNS()).as("/etc/hosts should contain the host 'oidcloginit.localhost' for this test to work").isTrue();

        subdomain = "oidcloginit";
        //identity client token
        identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );

        IdentityZoneConfiguration zoneConfiguration = new IdentityZoneConfiguration();
        //create the zone
        zone = IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, subdomain, subdomain, zoneConfiguration);
        adminToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");

        String zoneHost = zone.getSubdomain() + ".localhost";
        zoneUrl = "http://" + zoneHost + ":8080/uaa";

        String createdGroupName = new RandomValueStringGenerator(10).generate() + ".created.scope";


        String urlBase = "http://localhost:8080/uaa";
        identityProvider = new IdentityProvider<>();
        identityProvider.setName("my oidc provider");
        identityProvider.setIdentityZoneId(OriginKeys.UAA);
        OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition();
        config.setClientAuthInBody(false);
        config.addAttributeMapping(USER_NAME_ATTRIBUTE_NAME, "user_name");
        config.addAttributeMapping("given_name", "user_name");
        config.addAttributeMapping("user.attribute." + "the_client_id", "cid");
        config.addAttributeMapping("external_groups", "scope");

        config.setStoreCustomAttributes(true);

        config.addWhiteListedGroup("*");

        config.setAuthUrl(new URL(urlBase + "/oauth/authorize"));
        config.setTokenUrl(new URL(urlBase + "/oauth/token"));
        config.setTokenKeyUrl(new URL(urlBase + "/token_key"));
        config.setIssuer(urlBase + "/oauth/token");
        config.setUserInfoUrl(new URL(urlBase + "/userinfo"));
        config.setLogoutUrl(new URL(urlBase + "/logout.do"));

        config.setShowLinkText(true);
        config.setLinkText("My OIDC Provider");
        config.setSkipSslValidation(true);
        config.setRelyingPartyId("identity");
        config.setRelyingPartySecret("identitysecret");
        config.setScopes(List.of("openid", "cloud_controller.read"));
        identityProvider.setConfig(config);
        identityProvider.setOriginKey("puppy");
        identityProvider.setIdentityZoneId(zone.getId());
        identityProvider.setActive(true);
        clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");
        updateProvider();

        createdGroup = IntegrationTestUtils.createOrUpdateGroup(adminToken, subdomain, baseUrl, new ScimGroup(createdGroupName));
        ScimGroupExternalMember createdGroupExternalMapping = new ScimGroupExternalMember(createdGroup.getId(), "openid");
        createdGroupExternalMapping.setOrigin(identityProvider.getOriginKey());
        IntegrationTestUtils.mapExternalGroup(adminToken, subdomain, baseUrl, createdGroupExternalMapping);

        zoneClient = new UaaClientDetails(new RandomValueStringGenerator().generate(), null, "openid,user_attributes", "authorization_code,client_credentials", "uaa.admin,scim.read,scim.write,uaa.resource", zoneUrl);
        zoneClient.setClientSecret("secret");
        zoneClient.setAutoApproveScopes(Collections.singleton("true"));
        zoneClient = IntegrationTestUtils.createClientAsZoneAdmin(clientCredentialsToken, baseUrl, zone.getId(), zoneClient);
        zoneClient.setClientSecret("secret");

        doLogout(zoneUrl);
    }

    public void updateProvider() {
        identityProvider = IntegrationTestUtils.createOrUpdateProvider(clientCredentialsToken, baseUrl, identityProvider);
        assertThat(identityProvider.getConfig().getRelyingPartySecret()).isNull();
    }

    @AfterEach
    void tearDown() throws URISyntaxException {
        doLogout(zoneUrl);
        IntegrationTestUtils.deleteZone(baseUrl, zone.getId(), adminToken);
    }

    private void doLogout(String zoneUrl) {
        SamlLogoutAuthSourceEndpoint.assertThatLogoutAuthSource_goesToSamlWelcomePage(webDriver, samlServerConfig);
        webDriver.manage().deleteAllCookies();

        for (String url : Arrays.asList(baseUrl + "/logout.do", zoneUrl + "/logout.do")) {
            webDriver.get(url);
            webDriver.manage().deleteAllCookies();
        }
    }

    private void validateSuccessfulOIDCLogin(String zoneUrl, String userName, String password) {
        login(zoneUrl, userName, password);
        logout(zoneUrl);
        IntegrationTestUtils.validateAccountChooserCookie(zoneUrl, webDriver, IdentityZoneHolder.get());
    }

    private void logout(String zoneUrl) {
        webDriver.get(zoneUrl + "/logout.do");
        webDriver.get(zoneUrl + "/");
    }

    private void login(String zoneUrl, String userName, String password) {
        webDriver.get(zoneUrl + "/logout.do");
        webDriver.get(zoneUrl + "/");
        Cookie beforeLogin = webDriver.manage().getCookieNamed("JSESSIONID");
        assertThat(beforeLogin).isNotNull();
        assertThat(beforeLogin.getValue()).isNotNull();
        webDriver.clickAndWait(By.linkText("My OIDC Provider"));
        assertThat(webDriver.getCurrentUrl()).contains(baseUrl);

        webDriver.findElement(By.name("username")).sendKeys(userName);
        webDriver.findElement(By.name("password")).sendKeys(password);
        webDriver.clickAndWait(By.xpath("//input[@value='Sign in']"));
        assertThat(webDriver.getCurrentUrl()).contains(zoneUrl);
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Where to?");
        Cookie afterLogin = webDriver.manage().getCookieNamed("JSESSIONID");
        assertThat(afterLogin).isNotNull();
        assertThat(afterLogin.getValue()).isNotNull()
                .isNotEqualTo(beforeLogin.getValue());
    }

    @Test
    void successfulLoginWithOIDCProvider() {
        Long beforeTest = System.currentTimeMillis();
        validateSuccessfulOIDCLogin(zoneUrl, testAccounts.getUserName(), testAccounts.getPassword());
        Long afterTest = System.currentTimeMillis();
        String zoneAdminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "admin", "adminsecret");
        String origUserId = IntegrationTestUtils.getUserId(adminToken, baseUrl, "uaa", testAccounts.getUserName());
        ScimUser user = IntegrationTestUtils
                .getUserByZone(zoneAdminToken, baseUrl, subdomain, testAccounts.getUserName());
        IntegrationTestUtils.validateUserLastLogon(user, beforeTest, afterTest);
        assertThat(user.getExternalId()).isEqualTo(origUserId);
        assertThat(user.getUserName()).isEqualTo(user.getGivenName());
    }

    @Test
    void loginWithOIDCProviderUpdatesExternalId() {
        Long beforeTest = System.currentTimeMillis();

        String zoneAdminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "admin", "adminsecret");
        String zoneClientToken = IntegrationTestUtils.getClientCredentialsToken(zoneUrl, zoneClient.getClientId(), zoneClient.getClientSecret());
        ScimUser minimalShadowUser = new ScimUser();
        minimalShadowUser.setUserName(testAccounts.getUserName());
        minimalShadowUser.addEmail(testAccounts.getUserName());
        minimalShadowUser.setOrigin(identityProvider.getOriginKey());
        IntegrationTestUtils.createUser(zoneClientToken, zoneUrl, minimalShadowUser, null);
        ScimUser userCreated = IntegrationTestUtils.getUserByZone(zoneAdminToken, baseUrl, subdomain, testAccounts.getUserName());
        assertThat(StringUtils.hasText(userCreated.getExternalId())).isFalse();

        validateSuccessfulOIDCLogin(zoneUrl, testAccounts.getUserName(), testAccounts.getPassword());
        Long afterTest = System.currentTimeMillis();
        String origUserId = IntegrationTestUtils.getUserId(adminToken, baseUrl, "uaa", testAccounts.getUserName());
        ScimUser user = IntegrationTestUtils.getUserByZone(zoneAdminToken, baseUrl, subdomain, testAccounts.getUserName());
        IntegrationTestUtils.validateUserLastLogon(user, beforeTest, afterTest);
        assertThat(user.getExternalId()).isEqualTo(origUserId);
        assertThat(user.getUserName()).isEqualTo(user.getGivenName());
        assertThat(user.getExternalId()).isNotEmpty().doesNotContainOnlyWhitespaces();
    }

    @Test
    void loginWithInactiveProviderDoesNotWork() {
        webDriver.get(zoneUrl + "/logout.do");
        webDriver.get(zoneUrl + "/");
        Cookie beforeLogin = webDriver.manage().getCookieNamed("JSESSIONID");
        assertThat(beforeLogin).isNotNull();
        assertThat(beforeLogin.getValue()).isNotNull();
        String linkLocation = webDriver.findElement(By.linkText("My OIDC Provider")).getAttribute("href");

        identityProvider.setActive(false);
        updateProvider();

        webDriver.get(linkLocation);
        Page.assertThatUrlEventuallySatisfies(webDriver, asa -> asa.contains(baseUrl));

        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(testAccounts.getPassword());
        webDriver.clickAndWait(By.xpath("//input[@value='Sign in']"));
        Page.assertThatUrlEventuallySatisfies(webDriver, asa -> asa.contains(zoneUrl));

        assertThat(webDriver.getPageSource()).contains("Could not resolve identity provider with given origin.");
        webDriver.get(zoneUrl + "/");
        Page.assertThatUrlEventuallySatisfies(webDriver, urlAssert -> urlAssert.endsWith("/login"));
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Welcome to");
    }

    @Test
    void loginWithLoginHintUaa() {
        webDriver.get(zoneUrl + "/logout.do");
        String loginHint = URLEncoder.encode("{\"origin\":\"puppy\"}", StandardCharsets.UTF_8);

        webDriver.get(zoneUrl + "/login?login_hint=" + loginHint);
        assertThat(webDriver.getCurrentUrl()).startsWith(baseUrl);
    }

    @Test
    void successfulLoginWithOIDCProviderWithExternalGroups() {

        validateSuccessfulOIDCLogin(zoneUrl, testAccounts.getUserName(), testAccounts.getPassword());
        String anAdminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "admin", "adminsecret");
        ScimUser user = IntegrationTestUtils.getUserByZone(anAdminToken, baseUrl, subdomain, testAccounts.getUserName());
        assertThat(user.getUserName()).isEqualTo(user.getGivenName());

        ScimGroup updatedCreatedGroup = IntegrationTestUtils.getGroup(anAdminToken, subdomain, baseUrl, createdGroup.getDisplayName());
        assertThat(isMember(user.getId(), updatedCreatedGroup)).isTrue();
        assertThat(updatedCreatedGroup.getMembers().stream().allMatch(p -> user.getOrigin().equals(p.getOrigin()))).as("Expect group members to have origin: " + user.getOrigin()).isTrue();
    }

    @Test
    void successfulLoginWithOIDCProviderAndClientAuthInBody() {
        identityProvider.getConfig().setClientAuthInBody(true);
        assertThat(identityProvider.getConfig().isClientAuthInBody()).isTrue();
        updateProvider();
        assertThat(identityProvider.getConfig().isClientAuthInBody()).isTrue();
        validateSuccessfulOIDCLogin(zoneUrl, testAccounts.getUserName(), testAccounts.getPassword());
    }

    @Test
    void successfulLoginWithOIDCProviderSetsLastLogin() {
        login(zoneUrl, testAccounts.getUserName(), testAccounts.getPassword());
        doLogout(zoneUrl);
        login(zoneUrl, testAccounts.getUserName(), testAccounts.getPassword());
        assertThat(webDriver.findElement(By.cssSelector("#last_login_time"))).isNotNull();
    }

    @Test
    void successfulLoginWithOIDCProvider_MultiKeys() throws Exception {
        identityProvider.getConfig().setTokenKeyUrl(new URL(baseUrl + "/token_keys"));
        updateProvider();
        validateSuccessfulOIDCLogin(zoneUrl, testAccounts.getUserName(), testAccounts.getPassword());
    }

    @Test
    void login_with_wrong_keys() throws Exception {
        identityProvider.getConfig().setTokenKeyUrl(URI.create("https://login.microsoftonline.com/9bc40aaf-e150-4c30-bb3c-a8b3b677266e/discovery/v2.0/keys").toURL());
        updateProvider();
        webDriver.get(zoneUrl + "/login");
        webDriver.clickAndWait(By.linkText("My OIDC Provider"));
        assertThat(webDriver.getCurrentUrl()).contains(baseUrl);

        webDriver.findElement(By.name("username")).sendKeys("marissa");
        webDriver.findElement(By.name("password")).sendKeys("koala");
        webDriver.clickAndWait(By.xpath("//input[@value='Sign in']"));

        assertThat(webDriver.getCurrentUrl()).contains(zoneUrl + "/oauth_error")
                // no error as parameter sent
                .doesNotContain("?error=");
        assertThat(webDriver.findElement(By.cssSelector("h2")).getText()).contains("There was an error when authenticating against the external identity provider");

        List<String> cookies = IntegrationTestUtils.getAccountChooserCookies(zoneUrl, webDriver);
        assertThat(cookies).noneMatch(e -> e.startsWith("Saved-Account-"));
    }

    @Test
    void shadowUserNameDefaultsToOIDCSubjectClaim() {
        Map<String, Object> attributeMappings = new HashMap<>(identityProvider.getConfig().getAttributeMappings());
        attributeMappings.remove(USER_NAME_ATTRIBUTE_NAME);
        identityProvider.getConfig().setAttributeMappings(attributeMappings);
        updateProvider();

        webDriver.get(zoneUrl);
        webDriver.clickAndWait(By.linkText("My OIDC Provider"));

        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(testAccounts.getPassword());
        webDriver.clickAndWait(By.xpath("//input[@value='Sign in']"));

        webDriver.get(baseUrl);
        Cookie cookie = webDriver.manage().getCookieNamed("JSESSIONID");

        ServerRunningExtension localhostServerRunning = ServerRunningExtension.connect();
        localhostServerRunning.setHostName("localhost");

        String clientId = "client" + new RandomValueStringGenerator(5).generate();
        UaaClientDetails client = new UaaClientDetails(clientId, null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "openid", baseUrl);
        client.setClientSecret("clientsecret");
        client.setAutoApproveScopes(Collections.singletonList("true"));
        IntegrationTestUtils.createClient(adminToken, baseUrl, client);

        Map<String, String> authCodeTokenResponse = IntegrationTestUtils.getAuthorizationCodeTokenMap(localhostServerRunning,
                clientId,
                "clientsecret",
                null,
                null,
                "token id_token",
                cookie.getValue(),
                baseUrl,
                null,
                false);

        //validate that we have an ID token, and that it contains costCenter and manager values
        String idToken = authCodeTokenResponse.get("id_token");
        assertThat(idToken).isNotNull();

        Jwt idTokenClaims = JwtHelper.decode(idToken);
        Map<String, Object> claims = JsonUtils.readValue(idTokenClaims.getClaims(), new TypeReference<>() {
        });
        String expectedUsername = (String) claims.get(SUB);

        String anAdminToken = IntegrationTestUtils.getClientCredentialsToken(zoneUrl, zoneClient.getClientId(), zoneClient.getClientSecret());
        ScimUser shadowUser = IntegrationTestUtils.getUser(anAdminToken, zoneUrl, identityProvider.getOriginKey(), expectedUsername);
        assertThat(shadowUser.getUserName()).isEqualTo(expectedUsername);
    }

    @Test
    void successfulLoginWithOIDC_and_SAML_Provider_PlusRefreshRotation() throws Exception {
        SamlIdentityProviderDefinition saml = IntegrationTestUtils.createSimplePHPSamlIDP("simplesamlphp", OriginKeys.UAA, samlServerConfig.getSamlServerUrl());
        saml.setLinkText("SAML Login");
        saml.setShowSamlLink(true);
        IdentityProvider<SamlIdentityProviderDefinition> samlProvider = new IdentityProvider<>();
        samlProvider
                .setName("SAML to default zone")
                .setOriginKey(saml.getIdpEntityAlias())
                .setType(OriginKeys.SAML)
                .setConfig(saml)
                .setIdentityZoneId(saml.getZoneId());
        samlProvider = IntegrationTestUtils.createOrUpdateProvider(clientCredentialsToken, baseUrl, samlProvider);
        try {
            // This test creates an OIDC provider. That provider in turn has a SAML provider.
            // The end user is authenticated using OIDC federating to SAML
            webDriver.get(zoneUrl + "/login");
            webDriver.clickAndWait(By.linkText("My OIDC Provider"));
            assertThat(webDriver.getCurrentUrl()).contains(baseUrl);

            webDriver.clickAndWait(By.linkText("SAML Login"));
            webDriver.findElement(By.xpath(samlServerConfig.getLoginPromptXpathExpr()));
            webDriver.findElement(By.name("username")).clear();
            webDriver.findElement(By.name("username")).sendKeys("marissa6");
            webDriver.findElement(By.name("password")).sendKeys("saml6");
            webDriver.clickAndWait(By.id("submit_button"));

            Page.assertThatUrlEventuallySatisfies(webDriver, assertUrl -> assertUrl.startsWith(zoneUrl));
            assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Where to?");

            Cookie cookie = webDriver.manage().getCookieNamed("JSESSIONID");

            ServerRunningExtension zoneServerRunning = ServerRunningExtension.connect();
            zoneServerRunning.setHostName(zone.getSubdomain() + ".localhost");

            Map<String, String> authCodeTokenResponse = IntegrationTestUtils.getAuthorizationCodeTokenMap(zoneServerRunning,
                    zoneClient.getClientId(),
                    "secret",
                    null,
                    null,
                    "token id_token",
                    cookie.getValue(),
                    null,
                    null,
                    false);

            //validate that we have an ID token, and that it contains costCenter and manager values
            String idToken = authCodeTokenResponse.get("id_token");
            assertThat(idToken).isNotNull();

            Jwt idTokenClaims = JwtHelper.decode(idToken);
            Map<String, Object> claims = JsonUtils.readValue(idTokenClaims.getClaims(), new TypeReference<>() {
            });

            assertThat(claims)
                    .as("id_token should contain ACR claim")
                    .containsKey(ClaimConstants.ACR);
            Map<String, Object> acr = (Map<String, Object>) claims.get(ClaimConstants.ACR);
            assertThat((List<String>) acr.get("values"))
                    .as("acr claim should contain values attribute")
                    .contains(PASSWORD_AUTHN_CTX);
            UserInfoResponse userInfo = IntegrationTestUtils.getUserInfo(zoneUrl, authCodeTokenResponse.get("access_token"));

            Map<String, List<String>> userAttributeMap = userInfo.getUserAttributes();
            assertThat(userAttributeMap).isNotNull();
            List<String> clientIds = userAttributeMap.get("the_client_id");
            assertThat(clientIds).isNotNull();
            assertThat(clientIds.getFirst()).isEqualTo("identity");
            setRefreshTokenRotate(false);
            String refreshToken1 = getRefreshTokenResponse(zoneServerRunning, authCodeTokenResponse.get("refresh_token"));
            String refreshToken2 = getRefreshTokenResponse(zoneServerRunning, refreshToken1);
            assertThat(refreshToken2).as("New refresh token should be equal to the old one.").isEqualTo(refreshToken1);
            setRefreshTokenRotate(true);
            refreshToken1 = getRefreshTokenResponse(zoneServerRunning, refreshToken2);
            refreshToken2 = getRefreshTokenResponse(zoneServerRunning, refreshToken1);
            assertThat(refreshToken2).as("New access token should be different from the old one.").isNotEqualTo(refreshToken1);
        } finally {
            IntegrationTestUtils.deleteProvider(clientCredentialsToken, baseUrl, OriginKeys.UAA, samlProvider.getOriginKey());
        }
    }

    @Test
    void responseTypeRequired() {
        UaaClientDetails uaaClient = new UaaClientDetails(new RandomValueStringGenerator().generate(), null, "openid,user_attributes", "authorization_code,client_credentials", "uaa.admin,scim.read,scim.write,uaa.resource", baseUrl);
        uaaClient.setClientSecret("secret");
        uaaClient.setAutoApproveScopes(Collections.singleton("true"));
        uaaClient = IntegrationTestUtils.createClient(clientCredentialsToken, baseUrl, uaaClient);
        uaaClient.setClientSecret("secret");

        String uriBuilder = baseUrl + "/oauth/authorize" + "?scope=openid&client_id=" + uaaClient.getClientId() + "&redirect_uri=" + baseUrl;
        webDriver.get(uriBuilder);
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(testAccounts.getPassword());
        webDriver.clickAndWait(By.xpath("//input[@value='Sign in']"));

        assertThat(webDriver.getCurrentUrl()).contains("error=invalid_request")
                .contains("error_description=Missing%20response_type%20in%20authorization%20request");
    }

    @Test
    void successfulUaaLogoutTriggersExternalOIDCProviderLogout_whenConfiguredTo() {
        identityProvider.getConfig().setPerformRpInitiatedLogout(true);
        updateProvider();

        validateSuccessfulOIDCLogin(zoneUrl, testAccounts.getUserName(), testAccounts.getPassword());

        String externalOIDCProviderLoginPage = baseUrl;
        webDriver.get(externalOIDCProviderLoginPage);
        assertThat(webDriver.getCurrentUrl()).as("Did not land on the external OIDC provider login page (as an unauthenticated user).").endsWith("/login");
    }

    @Test
    void successfulUaaLogoutDoesNotTriggerExternalOIDCProviderLogout_whenConfiguredNotTo() {
        identityProvider.getConfig().setPerformRpInitiatedLogout(false);
        updateProvider();

        validateSuccessfulOIDCLogin(zoneUrl, testAccounts.getUserName(), testAccounts.getPassword());

        String externalOIDCProviderLoginPage = baseUrl;
        webDriver.get(externalOIDCProviderLoginPage);
        assertThat(webDriver.getPageSource()).as("Did not land on the external OIDC provider home page (as an authenticated user).").contains("Where to?");
    }

    private String getRefreshTokenResponse(ServerRunningExtension serverRunning, String refreshToken) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("client_id", zoneClient.getClientId());
        formData.add("client_secret", zoneClient.getClientSecret());
        formData.add("grant_type", "refresh_token");
        formData.add("refresh_token", refreshToken);
        serverRunning.setHostName(zone.getSubdomain() + ".localhost");
        HttpHeaders tokenHeaders = new HttpHeaders();
        tokenHeaders.set("Cache-Control", "no-store");
        ResponseEntity<Map> tokenResponse = serverRunning.postForMap("/oauth/token", formData, tokenHeaders);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(tokenResponse.getHeaders().getFirst("Cache-Control")).isEqualTo("no-store");
        return DefaultOAuth2AccessToken.valueOf(tokenResponse.getBody()).getRefreshToken().getValue();
    }

    private void setRefreshTokenRotate(boolean isRotate) {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        TokenPolicy policy = new TokenPolicy();
        policy.setRefreshTokenRotate(isRotate);
        policy.setRefreshTokenFormat(TokenConstants.TokenFormat.OPAQUE.getStringValue());
        config.setTokenPolicy(policy);
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zone.getId(), zone.getSubdomain(), config);
    }
}
