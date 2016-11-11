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
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.integration.util.ScreenshotOnFail;
import org.cloudfoundry.identity.uaa.login.test.LoginServerClassRunner;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
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
import org.springframework.security.jwt.Jwt;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.web.client.RestOperations;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.getZoneAdminToken;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

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

    private boolean isSetUp = false;
    private String originKey = null;

    @Before
    public void setUp() throws Exception {
        if (!isSetUp) {
            doLogout();
        }
        isSetUp = true;
        screenShootRule.setWebDriver(webDriver);
    }

    @After
    public void tearDown() {
        doLogout();
    }

    private void doLogout() {
        webDriver.get(baseUrl + "/logout.do");
        webDriver.manage().deleteAllCookies();
        webDriver.get("https://oidc10.identity.cf-app.com/logout.do");
        webDriver.get("http://simplesamlphp.cfapps.io/module.php/core/authenticate.php?as=example-userpass&logout");
    }

    @After
    public void deleteProvider() throws Exception {
        if (originKey!=null) {
            IntegrationTestUtils.deleteProvider(getZoneAdminToken(baseUrl, serverRunning), baseUrl, "uaa", originKey);
        }
    }

    @Test
    public void successfulLoginWithOIDCProvider() throws Exception {
        createOIDCProviderWithRequestedScopes();
        webDriver.get(baseUrl + "/login");
        webDriver.findElement(By.linkText("My OIDC Provider")).click();
        Assert.assertThat(webDriver.getCurrentUrl(), Matchers.containsString("oidc10.identity.cf-app.com"));

        webDriver.findElement(By.name("username")).sendKeys("marissa");
        webDriver.findElement(By.name("password")).sendKeys("koala");
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        Assert.assertThat(webDriver.getCurrentUrl(), Matchers.containsString("localhost"));
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Where to?"));

        webDriver.findElement(By.cssSelector(".dropdown-trigger")).click();
        webDriver.findElement(By.linkText("Sign Out")).click();
        IntegrationTestUtils.validateAccountChooserCookie(baseUrl, webDriver);
    }

    @Test
    public void successfulLoginWithOIDC_and_SAML_Provider() throws Exception {
        /*
          This test creates an OIDC provider. That provider in turn has a SAML provider.
          The end user is authenticated using
         */
        createOIDCProviderWithRequestedScopes();
        webDriver.get(baseUrl + "/login");
        webDriver.findElement(By.linkText("My OIDC Provider")).click();
        Assert.assertThat(webDriver.getCurrentUrl(), Matchers.containsString("oidc10.identity.cf-app.com"));

        webDriver.findElement(By.linkText("SAML Login")).click();
        webDriver.findElement(By.xpath("//h2[contains(text(), 'Enter your username and password')]"));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys("marissa6");
        webDriver.findElement(By.name("password")).sendKeys("saml6");
        webDriver.findElement(By.xpath("//input[@value='Login']")).click();

        Assert.assertThat(webDriver.getCurrentUrl(), Matchers.containsString("localhost"));
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Where to?"));

        Cookie cookie= webDriver.manage().getCookieNamed("JSESSIONID");
        System.out.println("cookie = " + String.format("%s=%s",cookie.getName(), cookie.getValue()));
        Map<String,String> authCodeTokenResponse = IntegrationTestUtils.getAuthorizationCodeTokenMap(serverRunning,
                                                                                                     UaaTestAccounts.standard(serverRunning),
                                                                                                     "login",
                                                                                                     "loginsecret",
                                                                                                     null,
                                                                                                     null,
                                                                                                     "token id_token",
                                                                                                     cookie.getValue(),
                                                                                                     baseUrl,
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
    }

    @Test
    public void successfulLoginWithOIDCProvider_withClientContext() throws Exception {
        createOIDCProviderWithRequestedScopes();
        webDriver.get(appUrl);

        webDriver.findElement(By.linkText("My OIDC Provider")).click();
        Assert.assertThat(webDriver.getCurrentUrl(), Matchers.containsString("oidc10.identity.cf-app.com"));

        webDriver.findElement(By.name("username")).sendKeys("marissa");
        webDriver.findElement(By.name("password")).sendKeys("koala");
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        Assert.assertThat(webDriver.getCurrentUrl(), Matchers.containsString("localhost"));
        Assert.assertEquals("Application Authorization", webDriver.findElement(By.cssSelector("h1")).getText());
    }

    @Test
    @Ignore("We don't have an azure provider pointint to http://localhost:8080/uaa anymore")
    public void successful_Azure_Login() throws Exception {
        String userName = "jondoe@cfuaa.onmicrosoft.com";
        String password = "Cona41591";
        IdentityProvider<OIDCIdentityProviderDefinition> azure = createAzureProvider();
        webDriver.get(appUrl);

        webDriver.findElement(By.linkText("Test Azure Provider")).click();
        String url = "login.microsoftonline.com/9bc40aaf-e150-4c30-bb3c-a8b3b677266e/oauth2/authorize";
        Assert.assertThat(webDriver.getCurrentUrl(), Matchers.containsString(url));

        webDriver.findElement(By.name("login")).sendKeys(userName);
        webDriver.findElement(By.name("passwd")).sendKeys(password);
        webDriver.findElement(By.name("passwd")).submit();
        //webDriver.findElement(By.id("credentials")).submit();

        Thread.sleep(500);
        Assert.assertEquals("Application Authorization", webDriver.findElement(By.cssSelector("h1")).getText());
    }

    @Test
    public void scopesIncludedInAuthorizeRequest() throws Exception {
        createOIDCProviderWithRequestedScopes();
        webDriver.get(appUrl);

        Assert.assertThat(webDriver.findElement(By.linkText("My OIDC Provider")).getAttribute("href"), Matchers.containsString("scope=openid+cloud_controller.read"));
    }

    @Test
    public void scopesIncludedInAuthorizeRequest_When_Issuer_Set() throws Exception {
        createOIDCProviderWithRequestedScopes("https://oidc10.identity.cf-app.com/oauth/token", "https://oidc10.identity.cf-app.com");
        try {
            webDriver.get(appUrl);
        } finally {
            IntegrationTestUtils.takeScreenShot(webDriver);
        }
        Assert.assertThat(webDriver.findElement(By.linkText("My OIDC Provider")).getAttribute("href"), Matchers.containsString("scope=openid+cloud_controller.read"));
    }

    private IdentityProvider<OIDCIdentityProviderDefinition> createAzureProvider() throws Exception {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = new IdentityProvider<>();
        identityProvider.setName("Test Azure Provider");
        identityProvider.setIdentityZoneId(OriginKeys.UAA);
        identityProvider.setType(OIDC10);
        identityProvider.setOriginKey("microsoft-azure");
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
        identityProvider.setConfig(config);
        String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");
        IdentityProvider<OIDCIdentityProviderDefinition> result = IntegrationTestUtils.createOrUpdateProvider(clientCredentialsToken, baseUrl, identityProvider);
        originKey = result.getOriginKey();
        return result;
    }

    private void createOIDCProviderWithRequestedScopes() throws Exception {
        createOIDCProviderWithRequestedScopes(null, "https://oidc10.identity.cf-app.com");
    }
    private void createOIDCProviderWithRequestedScopes(String issuer, final String urlBase) throws Exception {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = new IdentityProvider<>();
        identityProvider.setName("my oidc provider");
        identityProvider.setIdentityZoneId(OriginKeys.UAA);
        OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition();
        config.addAttributeMapping(USER_NAME_ATTRIBUTE_NAME, "user_name");
        config.setAuthUrl(new URL(urlBase + "/oauth/authorize"));
        config.setTokenUrl(new URL(urlBase + "/oauth/token"));
        config.setTokenKeyUrl(new URL(urlBase + "/token_key"));
        config.setShowLinkText(true);
        config.setLinkText("My OIDC Provider");
        config.setSkipSslValidation(true);
        config.setRelyingPartyId("identity");
        config.setRelyingPartySecret("identitysecret");
        config.setIssuer(issuer);
        List<String> requestedScopes = new ArrayList<>();
        requestedScopes.add("openid");
        requestedScopes.add("cloud_controller.read");
        config.setScopes(requestedScopes);
        identityProvider.setConfig(config);
        identityProvider.setOriginKey("puppy");
        String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");
        IntegrationTestUtils.createOrUpdateProvider(clientCredentialsToken, baseUrl, identityProvider);
        originKey = "puppy";
    }
}
