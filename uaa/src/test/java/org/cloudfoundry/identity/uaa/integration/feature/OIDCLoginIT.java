/*******************************************************************************
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

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.account.UserInfoResponse;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.integration.util.ScreenshotOnFail;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.WebDriver;
import org.opensaml.saml2.core.AuthnContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.net.Inet4Address;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.isMember;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SUB;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class OIDCLoginIT {

    @Autowired
    @Rule
    public IntegrationTestRule integrationTestRule;

    @Rule
    public ScreenshotOnFail screenShootRule = new ScreenshotOnFail();

    @Autowired
    RestOperations restOperations;

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Value("${integration.test.app_url}")
    String appUrl;

    @Autowired
    TestAccounts testAccounts;

    @Autowired
    TestClient testClient;

    private ServerRunning serverRunning = ServerRunning.isRunning();

    private IdentityZone zone;
    private String adminToken;
    private String subdomain;
    private String zoneUrl;
    private IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> identityProvider;
    private String clientCredentialsToken;
    private BaseClientDetails zoneClient;
    private ScimGroup createdGroup;

    @Before
    public void setUp() throws Exception {
        assertTrue("/etc/hosts should contain the host 'oidcloginit.localhost' for this test to work", doesSupportZoneDNS());

        screenShootRule.setWebDriver(webDriver);

        subdomain = "oidcloginit";
        //identity client token
        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
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

        config.setShowLinkText(true);
        config.setLinkText("My OIDC Provider");
        config.setSkipSslValidation(true);
        config.setRelyingPartyId("identity");
        config.setRelyingPartySecret("identitysecret");
        List<String> requestedScopes = new ArrayList<>();
        requestedScopes.add("openid");
        requestedScopes.add("cloud_controller.read");
        config.setScopes(requestedScopes);
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


        zoneClient = new BaseClientDetails(new RandomValueStringGenerator().generate(), null, "openid,user_attributes", "authorization_code,client_credentials", "uaa.admin,scim.read,scim.write,uaa.resource", zoneUrl);
        zoneClient.setClientSecret("secret");
        zoneClient.setAutoApproveScopes(Collections.singleton("true"));
        zoneClient = IntegrationTestUtils.createClientAsZoneAdmin(clientCredentialsToken, baseUrl, zone.getId(), zoneClient);
        zoneClient.setClientSecret("secret");

        doLogout(zoneUrl);
    }

    public void updateProvider() {
        identityProvider = IntegrationTestUtils.createOrUpdateProvider(clientCredentialsToken, baseUrl, identityProvider);
        assertNull(identityProvider.getConfig().getRelyingPartySecret());
    }

    public static boolean doesSupportZoneDNS() {
        try {
            return Arrays.equals(Inet4Address.getByName("oidcloginit.localhost").getAddress(), new byte[]{127, 0, 0, 1});
        } catch (UnknownHostException e) {
            return false;
        }
    }

    @After
    public void tearDown() throws URISyntaxException {
        doLogout(zoneUrl);
        IntegrationTestUtils.deleteZone(baseUrl, zone.getId(), adminToken);
    }

    private void doLogout(String zoneUrl) {
        for (String url : Arrays.asList(IntegrationTestUtils.SIMPLESAMLPHP_UAA_ACCEPTANCE + "/module.php/core/authenticate.php?as=example-userpass&logout", baseUrl + "/logout.do", zoneUrl + "/logout.do")) {
            webDriver.get(url);
            webDriver.manage().deleteAllCookies();
        }
    }

    private void validateSuccessfulOIDCLogin(String zoneUrl, String userName, String password) {
        login(zoneUrl, userName, password);

        webDriver.findElement(By.cssSelector(".dropdown-trigger")).click();
        webDriver.findElement(By.linkText("Sign Out")).click();
        IntegrationTestUtils.validateAccountChooserCookie(zoneUrl, webDriver, IdentityZoneHolder.get());
    }

    private void login(String zoneUrl, String userName, String password) {
        webDriver.get(zoneUrl + "/logout.do");
        webDriver.get(zoneUrl + "/");
        Cookie beforeLogin = webDriver.manage().getCookieNamed("JSESSIONID");
        assertNotNull(beforeLogin);
        assertNotNull(beforeLogin.getValue());
        webDriver.findElement(By.linkText("My OIDC Provider")).click();
        assertThat(webDriver.getCurrentUrl(), containsString(baseUrl));

        webDriver.findElement(By.name("username")).sendKeys(userName);
        webDriver.findElement(By.name("password")).sendKeys(password);
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
        Assert.assertThat(webDriver.getCurrentUrl(), containsString(zoneUrl));
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), containsString("Where to?"));
        Cookie afterLogin = webDriver.manage().getCookieNamed("JSESSIONID");
        assertNotNull(afterLogin);
        assertNotNull(afterLogin.getValue());
        assertNotEquals(beforeLogin.getValue(), afterLogin.getValue());
    }

    @Test
    public void successfulLoginWithOIDCProvider() {
        Long beforeTest = System.currentTimeMillis();
        validateSuccessfulOIDCLogin(zoneUrl, testAccounts.getUserName(), testAccounts.getPassword());
        Long afterTest = System.currentTimeMillis();
        String zoneAdminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "admin", "adminsecret");
        String origUserId = IntegrationTestUtils.getUserId(adminToken, baseUrl, "uaa", testAccounts.getUserName());
        ScimUser user = IntegrationTestUtils
                .getUserByZone(zoneAdminToken, baseUrl, subdomain, testAccounts.getUserName());
        IntegrationTestUtils.validateUserLastLogon(user, beforeTest, afterTest);
        assertEquals(origUserId, user.getExternalId());
        assertEquals(user.getGivenName(), user.getUserName());
    }

    @Test
    public void loginWithOIDCProviderUpdatesExternalId() {
        Long beforeTest = System.currentTimeMillis();

        String zoneAdminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "admin", "adminsecret");
        String zoneClientToken = IntegrationTestUtils.getClientCredentialsToken(zoneUrl, zoneClient.getClientId(), zoneClient.getClientSecret());
        ScimUser minimalShadowUser = new ScimUser();
        minimalShadowUser.setUserName(testAccounts.getUserName());
        minimalShadowUser.addEmail(testAccounts.getUserName());
        minimalShadowUser.setOrigin(identityProvider.getOriginKey());
        IntegrationTestUtils.createUser(zoneClientToken, zoneUrl, minimalShadowUser, null);
        ScimUser userCreated = IntegrationTestUtils.getUserByZone(zoneAdminToken, baseUrl, subdomain, testAccounts.getUserName());
        assertFalse(StringUtils.hasText(userCreated.getExternalId()));

        validateSuccessfulOIDCLogin(zoneUrl, testAccounts.getUserName(), testAccounts.getPassword());
        Long afterTest = System.currentTimeMillis();
        String origUserId = IntegrationTestUtils.getUserId(adminToken, baseUrl, "uaa", testAccounts.getUserName());
        ScimUser user = IntegrationTestUtils.getUserByZone(zoneAdminToken, baseUrl, subdomain, testAccounts.getUserName());
        IntegrationTestUtils.validateUserLastLogon(user, beforeTest, afterTest);
        assertEquals(origUserId, user.getExternalId());
        assertEquals(user.getGivenName(), user.getUserName());
        assertTrue(StringUtils.hasText(user.getExternalId()));
    }

    @Test
    public void testLoginWithInactiveProviderDoesNotWork() {
        webDriver.get(zoneUrl + "/logout.do");
        webDriver.get(zoneUrl + "/");
        Cookie beforeLogin = webDriver.manage().getCookieNamed("JSESSIONID");
        assertNotNull(beforeLogin);
        assertNotNull(beforeLogin.getValue());
        String linkLocation = webDriver.findElement(By.linkText("My OIDC Provider")).getAttribute("href");

        identityProvider.setActive(false);
        updateProvider();

        webDriver.get(linkLocation);
        Assert.assertThat(webDriver.getCurrentUrl(), containsString(baseUrl));

        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(testAccounts.getPassword());
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
        Assert.assertThat(webDriver.getCurrentUrl(), containsString(zoneUrl));
        assertThat(webDriver.getPageSource(), containsString("Could not resolve identity provider with given origin."));
        webDriver.get(zoneUrl + "/");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), containsString("Welcome to"));
    }

    @Test
    public void testLoginWithLoginHintUaa() {
        webDriver.get(zoneUrl + "/logout.do");
        String loginHint = URLEncoder.encode("{\"origin\":\"puppy\"}", StandardCharsets.UTF_8);

        webDriver.get(zoneUrl + "/login?login_hint=" + loginHint);

        Assert.assertThat(webDriver.getCurrentUrl(), startsWith(baseUrl));
    }

    @Test
    public void successfulLoginWithOIDCProviderWithExternalGroups() {

        validateSuccessfulOIDCLogin(zoneUrl, testAccounts.getUserName(), testAccounts.getPassword());
        String adminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "admin", "adminsecret");
        ScimUser user = IntegrationTestUtils.getUserByZone(adminToken, baseUrl, subdomain, testAccounts.getUserName());
        assertEquals(user.getGivenName(), user.getUserName());

        ScimGroup updatedCreatedGroup = IntegrationTestUtils.getGroup(adminToken, subdomain, baseUrl, createdGroup.getDisplayName());
        assertTrue(isMember(user.getId(), updatedCreatedGroup));
    }

    @Test
    public void successfulLoginWithOIDCProviderAndClientAuthInBody() {
        identityProvider.getConfig().setClientAuthInBody(true);
        assertTrue(identityProvider.getConfig().isClientAuthInBody());
        updateProvider();
        assertTrue(identityProvider.getConfig().isClientAuthInBody());
        validateSuccessfulOIDCLogin(zoneUrl, testAccounts.getUserName(), testAccounts.getPassword());
    }

    @Test
    public void successfulLoginWithOIDCProviderSetsLastLogin() {
        login(zoneUrl, testAccounts.getUserName(), testAccounts.getPassword());
        doLogout(zoneUrl);
        login(zoneUrl, testAccounts.getUserName(), testAccounts.getPassword());
        assertNotNull(webDriver.findElement(By.cssSelector("#last_login_time")));
    }

    @Test
    public void successfulLoginWithOIDCProvider_MultiKeys() throws Exception {
        identityProvider.getConfig().setTokenKeyUrl(new URL(baseUrl + "/token_keys"));
        updateProvider();
        validateSuccessfulOIDCLogin(zoneUrl, testAccounts.getUserName(), testAccounts.getPassword());
    }

    @Test
    public void login_with_wrong_keys() throws Exception {
        identityProvider.getConfig().setTokenKeyUrl(new URL("https://login.microsoftonline.com/9bc40aaf-e150-4c30-bb3c-a8b3b677266e/discovery/v2.0/keys"));
        updateProvider();
        webDriver.get(zoneUrl + "/login");
        webDriver.findElement(By.linkText("My OIDC Provider")).click();
        Assert.assertThat(webDriver.getCurrentUrl(), containsString(baseUrl));

        webDriver.findElement(By.name("username")).sendKeys("marissa");
        webDriver.findElement(By.name("password")).sendKeys("koala");
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        assertThat(webDriver.getCurrentUrl(), containsString(zoneUrl + "/oauth_error"));
        // no error as parameter sent
        assertThat(webDriver.getCurrentUrl(), not(containsString("?error=")));
        assertThat(webDriver.findElement(By.cssSelector("h2")).getText(), containsString("There was an error when authenticating against the external identity provider"));

        List<String> cookies = IntegrationTestUtils.getAccountChooserCookies(zoneUrl, webDriver);
        assertThat(cookies, not(Matchers.hasItem(startsWith("Saved-Account-"))));
    }

    @Test
    public void testShadowUserNameDefaultsToOIDCSubjectClaim() {
        Map<String, Object> attributeMappings = new HashMap<>(identityProvider.getConfig().getAttributeMappings());
        attributeMappings.remove(USER_NAME_ATTRIBUTE_NAME);
        identityProvider.getConfig().setAttributeMappings(attributeMappings);
        updateProvider();

        webDriver.get(zoneUrl);
        webDriver.findElement(By.linkText("My OIDC Provider")).click();

        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(testAccounts.getPassword());
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        webDriver.get(baseUrl);
        Cookie cookie = webDriver.manage().getCookieNamed("JSESSIONID");

        ServerRunning serverRunning = ServerRunning.isRunning();
        serverRunning.setHostName("localhost");

        String clientId = "client" + new RandomValueStringGenerator(5).generate();
        BaseClientDetails client = new BaseClientDetails(clientId, null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "openid", baseUrl);
        client.setClientSecret("clientsecret");
        client.setAutoApproveScopes(Collections.singletonList("true"));
        IntegrationTestUtils.createClient(adminToken, baseUrl, client);

        Map<String, String> authCodeTokenResponse = IntegrationTestUtils.getAuthorizationCodeTokenMap(serverRunning,
            UaaTestAccounts.standard(serverRunning),
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
        assertNotNull(idToken);

        Jwt idTokenClaims = JwtHelper.decode(idToken);
        Map<String, Object> claims = JsonUtils.readValue(idTokenClaims.getClaims(), new TypeReference<Map<String, Object>>() {
        });
        String expectedUsername = (String) claims.get(SUB);

        String adminToken = IntegrationTestUtils.getClientCredentialsToken(zoneUrl, zoneClient.getClientId(), zoneClient.getClientSecret());
        ScimUser shadowUser = IntegrationTestUtils.getUser(adminToken, zoneUrl, identityProvider.getOriginKey(), expectedUsername);
        assertEquals(expectedUsername, shadowUser.getUserName());
    }

    @Test
    public void successfulLoginWithOIDC_and_SAML_Provider() throws Exception {
        SamlIdentityProviderDefinition saml = IntegrationTestUtils.createSimplePHPSamlIDP("simplesamlphp", OriginKeys.UAA);
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

        /*
          This test creates an OIDC provider. That provider in turn has a SAML provider.
          The end user is authenticated using OIDC federating to SAML
         */
            webDriver.get(zoneUrl + "/login");
            webDriver.findElement(By.linkText("My OIDC Provider")).click();
            Assert.assertThat(webDriver.getCurrentUrl(), containsString(baseUrl));

            webDriver.findElement(By.linkText("SAML Login")).click();
            webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
            webDriver.findElement(By.name("username")).clear();
            webDriver.findElement(By.name("username")).sendKeys("marissa6");
            webDriver.findElement(By.name("password")).sendKeys("saml6");
            webDriver.findElement(By.xpath("//input[@value='Login']")).click();

            assertThat(webDriver.getCurrentUrl(), containsString(zoneUrl));
            assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), containsString("Where to?"));

            Cookie cookie = webDriver.manage().getCookieNamed("JSESSIONID");

            ServerRunning serverRunning = ServerRunning.isRunning();
            serverRunning.setHostName(zone.getSubdomain() + ".localhost");

            Map<String, String> authCodeTokenResponse = IntegrationTestUtils.getAuthorizationCodeTokenMap(serverRunning,
                UaaTestAccounts.standard(serverRunning),
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
            assertNotNull(idToken);

            Jwt idTokenClaims = JwtHelper.decode(idToken);
            Map<String, Object> claims = JsonUtils.readValue(idTokenClaims.getClaims(), new TypeReference<Map<String, Object>>() {
            });

            assertNotNull("id_token should contain ACR claim", claims.get(ClaimConstants.ACR));
            Map<String, Object> acr = (Map<String, Object>) claims.get(ClaimConstants.ACR);
            assertNotNull("acr claim should contain values attribute", acr.get("values"));
            assertThat((List<String>) acr.get("values"), containsInAnyOrder(AuthnContext.PASSWORD_AUTHN_CTX));

            UserInfoResponse userInfo = IntegrationTestUtils.getUserInfo(zoneUrl, authCodeTokenResponse.get("access_token"));

            Map<String, List<String>> userAttributeMap = userInfo.getUserAttributes();
            assertNotNull(userAttributeMap);
            List<String> clientIds = userAttributeMap.get("the_client_id");
            assertNotNull(clientIds);
            assertEquals("identity", clientIds.get(0));
        } finally {
            IntegrationTestUtils.deleteProvider(clientCredentialsToken, baseUrl, OriginKeys.UAA, samlProvider.getOriginKey());
        }
    }

    @Test
    public void testResponseTypeRequired() {
        BaseClientDetails uaaClient = new BaseClientDetails(new RandomValueStringGenerator().generate(), null, "openid,user_attributes", "authorization_code,client_credentials", "uaa.admin,scim.read,scim.write,uaa.resource", baseUrl);
        uaaClient.setClientSecret("secret");
        uaaClient.setAutoApproveScopes(Collections.singleton("true"));
        uaaClient = IntegrationTestUtils.createClient(clientCredentialsToken, baseUrl, uaaClient);
        uaaClient.setClientSecret("secret");

        StringBuilder uriBuilder = new StringBuilder();
        uriBuilder.append(baseUrl).append("/oauth/authorize").append("?scope=openid&client_id=").append(uaaClient.getClientId()).append("&redirect_uri=").append(baseUrl);
        webDriver.get(uriBuilder.toString());
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(testAccounts.getPassword());
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        assertThat(webDriver.getCurrentUrl(), containsString("error=invalid_request"));
        assertThat(webDriver.getCurrentUrl(), containsString("error_description=Missing%20response_type%20in%20authorization%20request"));
    }


    private OIDCIdentityProviderDefinition azureConfig() throws Exception {
        OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition();
        config.addAttributeMapping(USER_NAME_ATTRIBUTE_NAME, "unique_name");
        config.setAuthUrl(new URL("https://login.microsoftonline.com/9bc40aaf-e150-4c30-bb3c-a8b3b677266e/oauth2/authorize"));
        config.setTokenUrl(new URL("https://login.microsoftonline.com/9bc40aaf-e150-4c30-bb3c-a8b3b677266e/oauth2/token"));
        config.setTokenKeyUrl(new URL("https://login.microsoftonline.com/9bc40aaf-e150-4c30-bb3c-a8b3b677266e/discovery/v2.0/keys"));
        config.setShowLinkText(true);
        config.setLinkText("Test Azure Provider");
        config.setSkipSslValidation(false);
        config.setAddShadowUserOnLogin(true);
        config.setRelyingPartyId("8c5ea049-869e-47f8-a492-852a05f507af");
        config.setRelyingPartySecret(null);
        config.setIssuer("https://sts.windows.net/9bc40aaf-e150-4c30-bb3c-a8b3b677266e/");
        config.setScopes(Collections.singletonList("openid"));
        config.setResponseType("code id_token");
        return config;
    }

}
