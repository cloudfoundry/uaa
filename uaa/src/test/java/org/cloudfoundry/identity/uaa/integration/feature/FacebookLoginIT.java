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
import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.RawXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.RestOperations;

import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
@Ignore("Spotty test - stabilize first")
public class FacebookLoginIT {

    public static final String LINK_TEXT = "My Facebook Provider";
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

    private ServerRunning serverRunning = ServerRunning.isRunning();

    private String adminToken;
    private IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider;

    @Before
    public void setUp() throws Exception {
        screenShootRule.setWebDriver(webDriver);
        adminToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");

        RawXOAuthIdentityProviderDefinition config = new RawXOAuthIdentityProviderDefinition();
        config.setAuthUrl(new URL("https://www.facebook.com/dialog/oauth"));
        config.setTokenUrl(new URL("https://graph.facebook.com/oauth/access_token"));
        config.setIssuer("https://www.facebook.com");
        config.setShowLinkText(true);
        config.setLinkText(LINK_TEXT);
        config.setSkipSslValidation(true);
        config.setRelyingPartyId("1557898307566012");
        config.setRelyingPartySecret("db4fcbbb22fbb11644e507630ab498b9");
        config.setTokenKey("808c2ea930c55658aaaab0df8d6ba34c");
        config.setResponseType("signed_request");
        config.addAttributeMapping("user_name", "user_id");

        identityProvider = new IdentityProvider<>();
        identityProvider.setName("facebook provider");
        identityProvider.setIdentityZoneId(OriginKeys.UAA);
        identityProvider.setConfig(config);
        identityProvider.setOriginKey("fbIT");
        identityProvider.setIdentityZoneId(IdentityZone.getUaa().getId());
        identityProvider.setType(OriginKeys.OAUTH20);
        updateProvider();

        doLogout(baseUrl);
    }

    public void updateProvider() {
        identityProvider = IntegrationTestUtils.createOrUpdateProvider(adminToken, baseUrl, identityProvider);
        assertNull(identityProvider.getConfig().getRelyingPartySecret());
    }

    @After
    public void tearDown() throws URISyntaxException {
        doLogout(baseUrl);
    }

    private void doLogout(String zoneUrl) {
        for (String url : Arrays.asList("http://simplesamlphp.cfapps.io/module.php/core/authenticate.php?as=example-userpass&logout", baseUrl + "/logout.do", zoneUrl+"/logout.do"))  {
            webDriver.get(url);
            webDriver.manage().deleteAllCookies();
        }
    }

    @Test
    public void facebook_login() throws Exception {
        login(baseUrl, "cpchehishi_1505340052@tfbnw.net", "9zt7&1U#VEpk");

        webDriver.findElement(By.cssSelector(".dropdown-trigger")).click();
        webDriver.findElement(By.linkText("Sign Out")).click();
        IntegrationTestUtils.validateAccountChooserCookie(baseUrl, webDriver);
    }

    private void login(String url, String userName, String password) throws Exception {
        webDriver.get(url + "/logout.do");
        webDriver.get(url + "/");
        Cookie beforeLogin = webDriver.manage().getCookieNamed("JSESSIONID");
        assertNotNull(beforeLogin);
        assertNotNull(beforeLogin.getValue());
        webDriver.findElement(By.linkText(LINK_TEXT)).click();
        IntegrationTestUtils.takeScreenShot("test-screen-fb-before-login-", webDriver);
        Assert.assertThat(webDriver.getCurrentUrl(), Matchers.containsString("www.facebook.com"));
        IntegrationTestUtils.takeScreenShot("test-screen-fb-login-page-", webDriver);
        webDriver.findElement(By.name("email")).sendKeys(userName);
        webDriver.findElement(By.name("pass")).sendKeys(password);
        webDriver.findElement(By.name("login")).click();
        for (int i=0; i<5; i++) {
            IntegrationTestUtils.takeScreenShot("test-screen-fb-after-login-", webDriver);
            if (webDriver.getCurrentUrl().contains(url)) {
                break;
            } else {
                Thread.sleep(5000);
            }
        }
        Assert.assertThat(webDriver.getCurrentUrl(), Matchers.containsString(url));
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Where to?"));
        Cookie afterLogin = webDriver.manage().getCookieNamed("JSESSIONID");
        assertNotNull(afterLogin);
        assertNotNull(afterLogin.getValue());
        assertNotEquals(beforeLogin.getValue(), afterLogin.getValue());
    }



}
