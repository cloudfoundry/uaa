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

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;


import com.dumbster.smtp.SimpleSmtpServer;
import org.cloudfoundry.identity.uaa.ServerRunning;
import java.io.IOException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation.Banner;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.Links;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.assertSupportsZoneDNS;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CsrfPostProcessor.CSRF_PARAMETER_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class LoginIT {

    private final String USER_PASSWORD = "sec3Tas";

    @Autowired @Rule
    public IntegrationTestRule integrationTestRule;

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Autowired
    TestAccounts testAccounts;

    @Autowired
    TestClient testClient;

    @Autowired
    SimpleSmtpServer simpleSmtpServer;
    private static ServerRunning serverRunning = ServerRunning.isRunning();

    String originKey = "oidc-idp";

    @Before
    @After
    public void logout_and_clear_cookies() {
        try {
            webDriver.get(baseUrl + "/logout.do");
        }catch (org.openqa.selenium.TimeoutException x) {
            //try again - this should not be happening - 20 second timeouts
            webDriver.get(baseUrl + "/logout.do");
        }
        webDriver.manage().deleteAllCookies();
    }

    @Test
    public void check_JSESSIONID_defaults() {
        RestTemplate template = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        List<String> cookies;
        LinkedMultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("username", testAccounts.getUserName());
        requestBody.add("password", testAccounts.getPassword());

        headers.set(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE);
        ResponseEntity<String> loginResponse = template.exchange(baseUrl + "/login",
                                                                 HttpMethod.GET,
                                                                 new HttpEntity<>(null, headers),
                                                                 String.class);

        if (loginResponse.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : loginResponse.getHeaders().get("Set-Cookie")) {
                headers.add("Cookie", cookie);
            }
        }
        String csrf = IntegrationTestUtils.extracCsrfToken(loginResponse.getBody());
        requestBody.add(CSRF_PARAMETER_NAME, csrf);

        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        loginResponse = template.exchange(baseUrl + "/login.do",
                                          HttpMethod.POST,
                                          new HttpEntity<>(requestBody, headers),
                                          String.class);
        cookies = loginResponse.getHeaders().get("Set-Cookie");
        MatcherAssert.assertThat(cookies, hasItem(startsWith("JSESSIONID")));
        MatcherAssert.assertThat(cookies, hasItem(startsWith("Current-User")));
        headers.clear();
        boolean jsessionIdValidated = false;
        for (String cookie : loginResponse.getHeaders().get("Set-Cookie")) {
            if (cookie.contains("JSESSIONID")) {
                jsessionIdValidated = true;
                assertTrue(cookie.contains("HttpOnly"));
                assertFalse(cookie.contains("Secure"));

            }
        }
        assertTrue("Did not find JSESSIONID", jsessionIdValidated);
    }

    @Test
    @Ignore("To be ignored till ge branding for the new pivotal-ui-main.html layout")
    public void testBannerFunctionalityInDiscoveryPage() {
        String zoneId = "testzone3";

        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        Banner banner = new Banner();
        banner.setText("test banner");
        banner.setBackgroundColor("#444");
        banner.setTextColor("#111");
        config.setBranding(new BrandingInformation());
        config.getBranding().setBanner(banner);
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId, config);

        String zoneUrl = baseUrl.replace("localhost",zoneId+".localhost");
        webDriver.get(zoneUrl);
        webDriver.manage().deleteAllCookies();
        webDriver.navigate().refresh();
        assertEquals("test banner", webDriver.findElement(By.cssSelector(".banner-header span")).getText());
        assertEquals("rgba(68, 68, 68, 1)", webDriver.findElement(By.cssSelector(".banner-header")).getCssValue("background-color"));
        assertEquals("rgba(17, 17, 17, 1)", webDriver.findElement(By.cssSelector(".banner-header span")).getCssValue("color"));

        String base64Val = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAATBJREFUeNqk008og3Ecx/HNnrJSu63kIC5qKRe7KeUiOSulTHJUTrsr0y5ycFaEgyQXElvt5KDYwU0uO2hSUy4KoR7v7/qsfmjPHvzq1e/XU8/39/3zPFHf9yP/WV7jED24nGRbxDFWUAsToM05zyKFLG60d/wmQBxWzwyOlMU1phELEyCmtPeRQRoVbKOM0VYB6q0QW+3IYQpJFFDEYFCAiMqwNY857Ko3SxjGBTbRXb+xMUamcMbWh148YwJvOHSCdyqTAdxZo72ADGwKT98C9CChcxUPQSVYLz50toae4Fy9WcAISl7AiN/RhS1N5RV5rOLxx5eom90pvGAI/VjHMm6bfspK18a1gXvsqM41XDVL052C1Tim56cYd/rR+mdSrXGluxfm5S8Z/HV9CjAAvQZLXoa5mpgAAAAASUVORK5CYII=";
        banner.setLogo(base64Val);

        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId, config);
        webDriver.get(zoneUrl);

        assertEquals("data:image/png;base64," + base64Val, webDriver.findElement(By.cssSelector(".banner-header img")).getAttribute("src"));
        assertEquals(2, webDriver.findElement(By.cssSelector(".banner-header")).findElements(By.xpath(".//*")).size());
    }

    @Test
    public void testBannerBackgroundIsHiddenIfNoTextOrImage() {
        String zoneId = "testzone3";

        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        Banner banner = new Banner();
        banner.setLink("http://example.com");
        banner.setBackgroundColor("#444");
        banner.setTextColor("#111");
        config.setBranding(new BrandingInformation());
        config.getBranding().setBanner(banner);
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId, config);

        String zoneUrl = baseUrl.replace("localhost",zoneId+".localhost");
        webDriver.get(zoneUrl);
        webDriver.manage().deleteAllCookies();
        webDriver.navigate().refresh();
        assertEquals(0, webDriver.findElements(By.cssSelector(".banner-header")).size());
    }

    @Test
    public void testSuccessfulLoginNewUser() {
        String newUserEmail = createAnotherUser();
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(baseUrl + "/login");
        assertEquals("Predix", webDriver.getTitle());

        //assert Predix logo
        assertThat(webDriver.findElement(By.id("logo-header")).getAttribute("src"),
                containsString("predix-word.svg"));

        attemptLogin(newUserEmail, USER_PASSWORD);
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(),
                containsString("You should not see this page. Set up your redirect URI."));

        IntegrationTestUtils.validateAccountChooserCookie(baseUrl, webDriver, IdentityZoneHolder.get());
    }

    @Test
    public void testLoginHint() {
        String newUserEmail = createAnotherUser();
        webDriver.get(baseUrl + "/logout.do");
        String ldapLoginHint = URLEncoder.encode("{\"origin\":\"ldap\"}", StandardCharsets.UTF_8);
        webDriver.get(baseUrl + "/login?login_hint=" + ldapLoginHint);
        assertEquals("Predix", webDriver.getTitle());
        assertThat(webDriver.getPageSource(), not(containsString("or sign in with:")));
        attemptLogin(newUserEmail, USER_PASSWORD);
        assertThat(webDriver.findElement(By.className("alert-error")).getText(), containsString("Provided credentials are invalid. Please try again."));

        String uaaLoginHint = URLEncoder.encode("{\"origin\":\"uaa\"}", StandardCharsets.UTF_8);
        webDriver.get(baseUrl + "/login?login_hint=" + uaaLoginHint);
        assertEquals("Predix", webDriver.getTitle());
        assertThat(webDriver.getPageSource(), not(containsString("or sign in with:")));
        attemptLogin(newUserEmail, USER_PASSWORD);
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("You should not see this page. Set up your redirect URI."));
        webDriver.get(baseUrl + "/logout.do");
    }

    @Test
    public void testNoZoneFound() {
        assertSupportsZoneDNS();
        webDriver.get(baseUrl.replace("localhost","testzonedoesnotexist.localhost") + "/login");
        assertEquals("The subdomain does not map to a valid identity zone.",webDriver.findElement(By.tagName("p")).getText());
    }

    @Test
    public void testAutocompleteIsDisabledForPasswordField() {
        webDriver.get(baseUrl + "/login");
        WebElement password = webDriver.findElement(By.name("password"));
        assertEquals("off", password.getAttribute("autocomplete"));
    }

    @Test
    public void testPasscodeRedirect() {
        webDriver.get(baseUrl + "/passcode");
        assertEquals("Predix", webDriver.getTitle());

        attemptLogin(testAccounts.getUserName(), testAccounts.getPassword());

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), containsString("Temporary Authentication Code"));
    }

    @Test
    public void testUnsuccessfulLogin() {
        webDriver.get(baseUrl + "/login");
        assertEquals("Predix", webDriver.getTitle());

        attemptLogin(testAccounts.getUserName(), "invalidpassword");
        assertThat(webDriver.findElement(By.cssSelector("p")).getText(), containsString("Provided credentials are invalid. Please try again."));
    }

    @Test
    public void testAccessDeniedIfCsrfIsMissing() {
        RestTemplate template = new RestTemplate();
        template.setErrorHandler(new ResponseErrorHandler() {
            @Override
            public boolean hasError(ClientHttpResponse response) throws IOException {
                return response.getRawStatusCode() >= 500;
            }

            @Override
            public void handleError(ClientHttpResponse response) {
            }

        });
        LinkedMultiValueMap<String,String> body = new LinkedMultiValueMap<>();
        body.add("username", testAccounts.getUserName());
        body.add("password", testAccounts.getPassword());
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE);
        ResponseEntity<String> loginResponse = template.exchange(baseUrl + "/login.do",
            HttpMethod.POST,
            new HttpEntity<>(body, headers),
            String.class);
        assertEquals(HttpStatus.FOUND, loginResponse.getStatusCode());
        assertTrue("CSRF message should be shown", loginResponse.getHeaders().getFirst("Location").contains("invalid_login_request"));
    }

    @Test
    public void testRedirectAfterUnsuccessfulLogin() {
        RestTemplate template = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE);
        ResponseEntity<String> loginResponse = template.exchange(baseUrl + "/login",
            HttpMethod.GET,
            new HttpEntity<>(null, headers),
            String.class);

        if (loginResponse.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : loginResponse.getHeaders().get("Set-Cookie")) {
                headers.add("Cookie", cookie);
            }
        }
        String csrf = IntegrationTestUtils.extracCsrfToken(loginResponse.getBody());
        LinkedMultiValueMap<String,String> body = new LinkedMultiValueMap<>();
        body.add("username", testAccounts.getUserName());
        body.add("password", "invalidpassword");
        body.add(CSRF_PARAMETER_NAME, csrf);
        loginResponse = template.exchange(baseUrl + "/login.do",
            HttpMethod.POST,
            new HttpEntity<>(body, headers),
            String.class);
        assertEquals(HttpStatus.FOUND, loginResponse.getStatusCode());
    }

    @Test
    public void testLoginPageReloadBasedOnCsrf() {
        webDriver.get(baseUrl + "/login");
        assertTrue(webDriver.getPageSource().contains("http-equiv=\"refresh\""));
    }

    @Test
    public void userLockedoutAfterUnsuccessfulAttempts() {
        String userEmail = createAnotherUser();

        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(baseUrl + "/login");

        for (int i = 0; i < 5; i++) {
            attemptLogin(userEmail, "invalidpassword");
        }

        attemptLogin(userEmail, USER_PASSWORD);
        assertThat(webDriver.findElement(By.cssSelector(".alert-error")).getText(), containsString("Your account has been locked because of too many failed attempts to login."));
    }

    public void attemptLogin(String username, String password) {
        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.findElement(By.name("password")).sendKeys(password);
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
    }

    @Test
    public void testBuildInfo() {
        webDriver.get(baseUrl + "/login");

        String regex = "Version: \\S+, Commit: \\w{7}, Timestamp: .+, UAA: " + baseUrl;
        assertTrue(webDriver.findElement(By.cssSelector(".footer .copyright")).getAttribute("title").matches(regex));
    }

    @Test
    public void testAccountChooserManualLogin() throws Exception {
        String zoneUrl = createDiscoveryZone();

        String userEmail = createAnotherUser(zoneUrl);
        webDriver.get(zoneUrl + "/logout.do");
        webDriver.manage().deleteAllCookies();
        webDriver.get(zoneUrl);

        loginThroughDiscovery(userEmail, USER_PASSWORD);
        webDriver.get(zoneUrl + "/logout.do");

        webDriver.get(zoneUrl);
        assertEquals("Sign in to another account", webDriver.findElement(By.cssSelector("div.action a")).getText());
        webDriver.findElement(By.cssSelector("div.action a")).click();

        loginThroughDiscovery(userEmail, USER_PASSWORD);
        assertThat(webDriver.findElement(By.cssSelector(".island h1")).getText(),
                containsString("You should not see this page. Set up your redirect URI."));
        deleteDiscoveryZoneIdentityProvider();

    }

    @Test
    public void testAccountChooserFlow()  throws Exception {
        String zoneUrl = createDiscoveryZone();

        String userEmail = createAnotherUser(zoneUrl);
        webDriver.get(zoneUrl + "/logout.do");
        webDriver.get(zoneUrl);

        loginThroughDiscovery(userEmail, USER_PASSWORD);
        webDriver.get(zoneUrl + "/logout.do");

        webDriver.get(zoneUrl);
        assertThat(webDriver.findElement(By.className("email-address")).getText(), startsWith(userEmail));
        assertThat(webDriver.findElement(By.className("email-address")).getText(), containsString(OriginKeys.UAA));
        webDriver.findElement(By.className("email-address")).click();

        assertEquals(userEmail, webDriver.findElement(By.id("username")).getAttribute("value"));
        assertThat(webDriver.getCurrentUrl(), containsString("login_hint"));
        webDriver.findElement(By.id("password")).sendKeys(USER_PASSWORD);
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
        assertThat(webDriver.findElement(By.cssSelector(".island h1")).getText(),
                containsString("You should not see this page. Set up your redirect URI."));
        deleteDiscoveryZoneIdentityProvider();
    }

    @Test
    public void testAccountChooserPopulatesUsernameNotEmailWhenOriginIsUAAorLDAP() throws Exception {
        String userUAA = "{\"userId\":\"1\",\"username\":\"userUAA\",\"origin\":\"uaa\",\"email\":\"user@uaa.org\"}";
        String userLDAP = "{\"userId\":\"2\",\"username\":\"userLDAP\",\"origin\":\"ldap\",\"email\":\"user@ldap.org\"}";
        String userExternal = "{\"userId\":\"3\",\"username\":\"userExternal\",\"origin\":\"external\",\"email\":\"user@external.org\"}";

        String zoneUrl = createDiscoveryZone();
        webDriver.get(zoneUrl);

        webDriver.manage().deleteAllCookies();
        JavascriptExecutor js = (JavascriptExecutor) webDriver;
        js.executeScript("document.cookie = \"Saved-Account-1=" + URLEncoder.encode(userUAA, StandardCharsets.UTF_8.name()) + ";path=/;domain=testzone3.localhost\"");
        js.executeScript("document.cookie = \"Saved-Account-2=" + URLEncoder.encode(userLDAP, StandardCharsets.UTF_8.name()) + ";path=/;domain=testzone3.localhost\"");
        js.executeScript("document.cookie = \"Saved-Account-3=" + URLEncoder.encode(userExternal, StandardCharsets.UTF_8.name()) + ";path=/;domain=testzone3.localhost\"");

        webDriver.navigate().refresh();
        assertEquals(3, webDriver.findElements(By.cssSelector("span.email-address")).size());

        webDriver.findElement(By.xpath("//span[contains(text(), 'userUAA')]")).click();
        assertEquals("userUAA", webDriver.findElement(By.id("username")).getAttribute("value"));
        webDriver.navigate().back();

        webDriver.findElement(By.xpath("//span[contains(text(), 'userLDAP')]")).click();
        assertEquals("userLDAP", webDriver.findElement(By.id("username")).getAttribute("value"));
        webDriver.navigate().back();

        webDriver.findElement(By.xpath("//span[contains(text(), 'userExternal')]")).click();
        assertEquals("user@external.org", webDriver.findElement(By.id("username")).getAttribute("value"));

        webDriver.manage().deleteAllCookies();
        deleteDiscoveryZoneIdentityProvider();
    }

    @Test
    public void testLoginReloadRetainsFormRedirect() {

        String redirectUri = "http://expected.com";
        webDriver.get(baseUrl + "/oauth/authorize?client_id=test&redirect_uri="+redirectUri);
        ((JavascriptExecutor)webDriver).executeScript("document.getElementsByName('" + CSRF_PARAMETER_NAME + "')[0].value=''");
        webDriver.manage().deleteCookieNamed("JSESSIONID");

        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        assertThat(webDriver.getCurrentUrl(), containsString("/login"));
        assertThat(webDriver.findElement(By.name("form_redirect_uri")).getAttribute("value"), containsString("redirect_uri="+redirectUri));

    }

    private String createAnotherUser() {
        return createAnotherUser(baseUrl);
    }

    private String createAnotherUser(String url) {
        return IntegrationTestUtils.createAnotherUser(webDriver, USER_PASSWORD, simpleSmtpServer, url, testClient);
    }

    private String createDiscoveryZone() throws Exception {
        String testzone3 = "testzone3";

        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        config.setAccountChooserEnabled(true);
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, testzone3, testzone3, config);
        IdentityProvider provider = new IdentityProvider();
        provider.setIdentityZoneId(testzone3);
        provider.setType(OriginKeys.OIDC10);
        provider.setActive(true);
        provider.setOriginKey(originKey);
        provider.setName(originKey);
        OIDCIdentityProviderDefinition oidcConfig = new OIDCIdentityProviderDefinition();
        oidcConfig.addAttributeMapping(USER_NAME_ATTRIBUTE_NAME, "user_name");
        oidcConfig.setAuthUrl(new URL("https://oidc10.oms.identity.team/oauth/authorize"));
        oidcConfig.setTokenUrl(new URL("https://oidc10.oms.identity.team/oauth/token"));
        oidcConfig.setTokenKeyUrl(new URL("https://oidc10.oms.identity.team/token_key"));
        oidcConfig.setShowLinkText(true);
        oidcConfig.setLinkText("My OIDC Provider");
        oidcConfig.setSkipSslValidation(true);
        oidcConfig.setRelyingPartyId("identity");
        oidcConfig.setRelyingPartySecret("identitysecret");
        oidcConfig.setEmailDomain(Collections.singletonList("test.org"));
        provider.setConfig(oidcConfig);

        String zoneAdminToken = IntegrationTestUtils.getZoneAdminToken(baseUrl, serverRunning, testzone3);
        IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        String res = baseUrl.replace("localhost", testzone3 +".localhost");
        webDriver.get(res + "/logout.do");
        webDriver.manage().deleteAllCookies();
        return res;
    }

    private void deleteDiscoveryZoneIdentityProvider() {
        String testzone3 = "testzone3";
        String zoneAdminToken = IntegrationTestUtils.getZoneAdminToken(baseUrl, serverRunning, testzone3);
        IntegrationTestUtils.deleteProvider(zoneAdminToken, baseUrl, testzone3, originKey);
    }

    private void loginThroughDiscovery(String userEmail, String password) {
        webDriver.findElement(By.id("email")).sendKeys(userEmail);
        webDriver.findElement(By.cssSelector(".form-group input[value='Next']")).click();
        webDriver.findElement(By.id("password")).sendKeys(password);
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
    }

    @Test
    public void testSelfServiceLinksBehavior() {
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret"));
        String zoneId = "testzone3";
        String zoneUrl = baseUrl.replace("localhost", zoneId+".localhost");
        IdentityZone testZone3 = IntegrationTestUtils.createZoneOrUpdateSubdomain(adminClient, baseUrl, zoneId, zoneId, new IdentityZoneConfiguration());

        testZone3.getConfig().getLinks().setSelfService(new Links.SelfService().setSelfServiceLinksEnabled(true).setPasswd("").setSignup(""));
        IntegrationTestUtils.createZoneOrUpdateSubdomain(adminClient, baseUrl, zoneId, zoneId, testZone3.getConfig());
        webDriver.get(zoneUrl);
        assertEquals(0, webDriver.findElements(By.xpath("//*[text()='Create account']")).size());
        assertEquals(0, webDriver.findElements(By.xpath("//*[text()='Reset password']")).size());

        testZone3.getConfig().getLinks().setSelfService(new Links.SelfService().setSelfServiceLinksEnabled(true).setPasswd("/forgot_password").setSignup("http://example.com"));
        IntegrationTestUtils.createZoneOrUpdateSubdomain(adminClient, baseUrl, zoneId, zoneId, testZone3.getConfig());
        webDriver.get(zoneUrl);
        assertEquals(1, webDriver.findElements(By.xpath("//*[text()='Create account']")).size());
        assertEquals(1, webDriver.findElements(By.xpath("//*[text()='Reset password']")).size());

        testZone3.getConfig().getLinks().setSelfService(new Links.SelfService().setSelfServiceLinksEnabled(true).setPasswd(null).setSignup(null));
        IntegrationTestUtils.createZoneOrUpdateSubdomain(adminClient, baseUrl, zoneId, zoneId, testZone3.getConfig());
        webDriver.get(zoneUrl);
        assertEquals(0, webDriver.findElements(By.xpath("//*[text()='Create account']")).size());
        assertEquals(1, webDriver.findElements(By.xpath("//*[text()='Reset password']")).size());

        testZone3.getConfig().getLinks().setSelfService(new Links.SelfService().setSelfServiceLinksEnabled(true).setPasswd("/forgot_password").setSignup("/create_account"));
        IntegrationTestUtils.createZoneOrUpdateSubdomain(adminClient, baseUrl, zoneId, zoneId, testZone3.getConfig());

    }
}
