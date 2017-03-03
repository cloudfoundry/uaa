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
import org.cloudfoundry.identity.uaa.login.test.LoginServerClassRunner;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
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
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.net.Inet4Address;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ATTRIBUTES;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assume.assumeTrue;

@RunWith(LoginServerClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class OIDCLoginIT {

    @Autowired @Rule
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

    ServerRunning serverRunning = ServerRunning.isRunning();

    private String originKey = null;
    private IdentityZone zone;
    private String adminToken;
    private String subdomain;
    private String zoneHost;
    private String zoneUrl;
    private IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider;
    private String clientCredentialsToken;
    private BaseClientDetails zoneClient;

    @Before
    public void setUp() throws Exception {
        assumeTrue("/etc/hosts should contain the host 'oidcloginit.localhost' for this test to work", doesSupportZoneDNS());

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

        zoneHost = zone.getSubdomain()+".localhost";
        zoneUrl = "http://"+ zoneHost + ":8080/uaa";


        String urlBase = "http://localhost:8080/uaa";
        identityProvider = new IdentityProvider<>();
        identityProvider.setName("my oidc provider");
        identityProvider.setIdentityZoneId(OriginKeys.UAA);
        OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition();
        config.addAttributeMapping(USER_NAME_ATTRIBUTE_NAME, "user_name");
        config.addAttributeMapping("user.attribute." + "the_client_id", "cid");
        config.setStoreCustomAttributes(true);

        config.setAuthUrl(new URL(urlBase + "/oauth/authorize"));
        config.setTokenUrl(new URL(urlBase + "/oauth/token"));
        config.setTokenKeyUrl(new URL(urlBase + "/token_key"));
        config.setIssuer(urlBase + "/oauth/token");
        config.setUserInfoUrl(new URL(urlBase+"/userinfo"));

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
        clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");
        updateProvider();
        originKey = "puppy";

        zoneClient = new BaseClientDetails(new RandomValueStringGenerator().generate(), null, "openid,user_attributes", "authorization_code,client_credentials", "uaa.admin,scim.read,scim.write,uaa.resource", zoneUrl);
        zoneClient.setClientSecret("secret");
        zoneClient.setAutoApproveScopes(Collections.singleton("true"));
        zoneClient = IntegrationTestUtils.createClientAsZoneAdmin(clientCredentialsToken, baseUrl, zone.getId(), zoneClient);
        zoneClient.setClientSecret("secret");

        doLogout(zoneUrl);
    }

    public void updateProvider() {
        identityProvider = IntegrationTestUtils.createOrUpdateProvider(clientCredentialsToken, baseUrl, identityProvider);
    }

    public static boolean doesSupportZoneDNS() {
        try {
            return Arrays.equals(Inet4Address.getByName("oidcloginit.localhost").getAddress(), new byte[] {127,0,0,1});
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
        for (String url : Arrays.asList("http://simplesamlphp.cfapps.io/module.php/core/authenticate.php?as=example-userpass&logout", baseUrl + "/logout.do", zoneUrl+"/logout.do"))  {
            webDriver.get(url);
            webDriver.manage().deleteAllCookies();
        }
    }

    private void validateSuccessfulOIDCLogin(String zoneUrl, String userName, String password) {
        login(zoneUrl, userName, password);
    }

    private void login(String zoneUrl, String userName, String password) {
        webDriver.get(zoneUrl + "/logout.do");
        webDriver.get(zoneUrl + "/");
        Cookie beforeLogin = webDriver.manage().getCookieNamed("JSESSIONID");
        assertNotNull(beforeLogin);
        assertNotNull(beforeLogin.getValue());
        webDriver.findElement(By.linkText("My OIDC Provider")).click();
        Assert.assertThat(webDriver.getCurrentUrl(), Matchers.containsString(baseUrl));

        webDriver.findElement(By.name("username")).sendKeys(userName);
        webDriver.findElement(By.name("password")).sendKeys(password);
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
        Assert.assertThat(webDriver.getCurrentUrl(), Matchers.containsString(zoneUrl));
        Assert.assertThat(webDriver.getCurrentUrl(), Matchers.containsString("localhost"));
        Cookie afterLogin = webDriver.manage().getCookieNamed("JSESSIONID");
        assertNotNull(afterLogin);
        assertNotNull(afterLogin.getValue());

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(),
                //Predix specific message on landing page.
                Matchers.containsString("You should not see this page. Set up your redirect URI."));
        IntegrationTestUtils.validateAccountChooserCookie(baseUrl, webDriver);
    }

    @Test
    public void successfulLoginWithOIDCProvider() throws Exception {
        Long beforeTest = System.currentTimeMillis();
        validateSuccessfulOIDCLogin(zoneUrl, testAccounts.getUserName(), testAccounts.getPassword());
        Long afterTest = System.currentTimeMillis();
        String zoneAdminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "admin", "adminsecret");
        ScimUser user = IntegrationTestUtils.getUserByZone(zoneAdminToken, baseUrl, subdomain, testAccounts.getUserName());
        IntegrationTestUtils.validateUserLastLogon(user, beforeTest, afterTest);
    }

    @Test
    public void successfulLoginWithOIDCProvider_MultiKeys() throws Exception {
        identityProvider.getConfig().setTokenKeyUrl(new URL(baseUrl+"/token_keys"));
        updateProvider();
        validateSuccessfulOIDCLogin(zoneUrl, testAccounts.getUserName(), testAccounts.getPassword());
    }

    @Test
    public void login_with_wrong_keys() throws Exception {
        identityProvider.getConfig().setTokenKeyUrl(new URL("https://login.microsoftonline.com/9bc40aaf-e150-4c30-bb3c-a8b3b677266e/discovery/v2.0/keys"));
        updateProvider();
        webDriver.get(zoneUrl + "/login");
        webDriver.findElement(By.linkText("My OIDC Provider")).click();
        Assert.assertThat(webDriver.getCurrentUrl(), Matchers.containsString(baseUrl));

        webDriver.findElement(By.name("username")).sendKeys("marissa");
        webDriver.findElement(By.name("password")).sendKeys("koala");
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        Assert.assertThat(webDriver.getCurrentUrl(), Matchers.containsString(zoneUrl + "/oauth_error?error=There+was+an+error+when+authenticating+against+the+external+identity+provider"));

        List<String> cookies = IntegrationTestUtils.getAccountChooserCookies(zoneUrl, webDriver);
        assertThat(cookies, not(Matchers.hasItem(startsWith("Saved-Account-"))));
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
            Assert.assertThat(webDriver.getCurrentUrl(), Matchers.containsString(baseUrl));

            webDriver.findElement(By.linkText("SAML Login")).click();
            webDriver.findElement(By.xpath("//h2[contains(text(), 'Enter your username and password')]"));
            webDriver.findElement(By.name("username")).clear();
            webDriver.findElement(By.name("username")).sendKeys("marissa6");
            webDriver.findElement(By.name("password")).sendKeys("saml6");
            webDriver.findElement(By.xpath("//input[@value='Login']")).click();

            Assert.assertThat(webDriver.getCurrentUrl(), Matchers.containsString(zoneUrl));
            assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("You should not see this page. Set up your redirect URI."));

            Cookie cookie= webDriver.manage().getCookieNamed("JSESSIONID");
            System.out.println("cookie = " + String.format("%s=%s",cookie.getName(), cookie.getValue()));

            ServerRunning serverRunning = ServerRunning.isRunning();
            serverRunning.setHostName(zone.getSubdomain()+".localhost");

            Map<String,String> authCodeTokenResponse = IntegrationTestUtils.getAuthorizationCodeTokenMap(serverRunning,
                                                                                                         UaaTestAccounts.standard(serverRunning),
                                                                                                         zoneClient.getClientId(),
                                                                                                         "secret",
                                                                                                         null,
                                                                                                         null,
                                                                                                         "token id_token",
                                                                                                         cookie.getValue(),
                                                                                                         null,
                                                                                                         false);

            //validate that we have an ID token, and that it contains costCenter and manager values
            String idToken = authCodeTokenResponse.get("id_token");
            assertNotNull(idToken);

            Jwt idTokenClaims = JwtHelper.decode(idToken);
            Map<String, Object> claims = JsonUtils.readValue(idTokenClaims.getClaims(), new TypeReference<Map<String, Object>>() {});

            assertNotNull("id_token should contain ACR claim", claims.get(ClaimConstants.ACR));
            Map<String,Object> acr = (Map<String, Object>) claims.get(ClaimConstants.ACR);
            assertNotNull("acr claim should contain values attribute", acr.get("values"));
            assertThat((List<String>) acr.get("values"), containsInAnyOrder(AuthnContext.PASSWORD_AUTHN_CTX));

            UserInfoResponse userInfo = IntegrationTestUtils.getUserInfo(zoneUrl, authCodeTokenResponse.get("access_token"));

            Map<String,List<String>> userAttributeMap = (Map<String,List<String>>) userInfo.getAttributeValue(USER_ATTRIBUTES);
            assertNotNull(userAttributeMap);
            List<String> clientIds = userAttributeMap.get("the_client_id");
            assertNotNull(clientIds);
            assertEquals("identity", clientIds.get(0));
        } finally {
            IntegrationTestUtils.deleteProvider(clientCredentialsToken, baseUrl, OriginKeys.UAA, samlProvider.getOriginKey());
        }
    }

    @Test
    @Ignore("We don't have an azure provider pointint to http://oidcloginit.localhost:8080/uaa anymore")
    public void successful_Azure_Login() throws Exception {
        String userName = "jondoe@cfuaa.onmicrosoft.com";
        String password = "Cona41591";
        OIDCIdentityProviderDefinition azureConfig = azureConfig();
        azureConfig.setLinkText("Test Azure Provider");
        azureConfig.setShowLinkText(true);
        identityProvider.setConfig(azureConfig);
        updateProvider();

        webDriver.get(zoneUrl);

        webDriver.findElement(By.linkText("Test Azure Provider")).click();
        String url = "login.microsoftonline.com/9bc40aaf-e150-4c30-bb3c-a8b3b677266e/oauth2/authorize";
        Assert.assertThat(webDriver.getCurrentUrl(), Matchers.containsString(url));

        webDriver.findElement(By.name("login")).sendKeys(userName);
        webDriver.findElement(By.name("passwd")).sendKeys(password);
        webDriver.findElement(By.name("passwd")).submit();

        Thread.sleep(500);
        Assert.assertThat(webDriver.getCurrentUrl(), Matchers.containsString(zoneUrl));
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Where to?"));
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
        config.setScopes(Arrays.asList("openid"));
        config.setResponseType("code id_token");
        return config;
    }

}
