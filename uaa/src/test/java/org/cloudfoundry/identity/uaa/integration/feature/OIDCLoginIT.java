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

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.integration.util.ScreenshotOnFail;
import org.cloudfoundry.identity.uaa.login.test.LoginServerClassRunner;
import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.XOIDCIdentityProviderDefinition;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.web.client.RestOperations;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.getZoneAdminToken;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
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

    @Before
    @After
    public void logout() throws Exception {
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get("https://oidc10.identity.cf-app.com/logout.do");
        screenShootRule.setWebDriver(webDriver);
    }

    @After
    public void deleteProvider() throws Exception {
        IntegrationTestUtils.deleteProvider(getZoneAdminToken(baseUrl, serverRunning), baseUrl, "uaa", "puppy");
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
    public void scopesIncludedInAuthorizeRequest() throws Exception {
        createOIDCProviderWithRequestedScopes();
        webDriver.get(appUrl);

        Assert.assertThat(webDriver.findElement(By.linkText("My OIDC Provider")).getAttribute("href"), Matchers.containsString("scope=openid+cloud_controller.read"));
    }

    @Test
    public void scopesIncludedInAuthorizeRequest_When_Issuer_Set() throws Exception {
        createOIDCProviderWithRequestedScopes("https://oidc10.identity.cf-app.com/oauth/token");
        try {
            webDriver.get(appUrl);
        } finally {
            IntegrationTestUtils.takeScreenShot(webDriver);
        }
        Assert.assertThat(webDriver.findElement(By.linkText("My OIDC Provider")).getAttribute("href"), Matchers.containsString("scope=openid+cloud_controller.read"));
    }

    private void createOIDCProviderWithRequestedScopes() throws Exception {
        createOIDCProviderWithRequestedScopes(null);
    }
    private void createOIDCProviderWithRequestedScopes(String issuer) throws Exception {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = new IdentityProvider<>();
        identityProvider.setName("my oidc provider");
        identityProvider.setIdentityZoneId(OriginKeys.UAA);
        XOIDCIdentityProviderDefinition config = new XOIDCIdentityProviderDefinition();
        config.addAttributeMapping(USER_NAME_ATTRIBUTE_NAME, "user_name");
        config.setAuthUrl(new URL("https://oidc10.identity.cf-app.com/oauth/authorize"));
        config.setTokenUrl(new URL("https://oidc10.identity.cf-app.com/oauth/token"));
        config.setTokenKeyUrl(new URL("https://oidc10.identity.cf-app.com/token_key"));
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
    }
}
