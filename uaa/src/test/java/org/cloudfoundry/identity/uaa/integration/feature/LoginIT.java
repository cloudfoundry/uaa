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

import com.dumbster.smtp.SimpleSmtpServer;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation.Banner;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
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

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.doesSupportZoneDNS;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

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
    private String testzone3;

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
    public void check_JSESSIONID_defaults() throws Exception {
        RestTemplate template = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        List<String> cookies = Collections.EMPTY_LIST;
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
        String csrf = IntegrationTestUtils.extractCookieCsrf(loginResponse.getBody());
        requestBody.add(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, csrf);

        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        loginResponse = template.exchange(baseUrl + "/login.do",
                                          HttpMethod.POST,
                                          new HttpEntity<>(requestBody, headers),
                                          String.class);
        cookies = loginResponse.getHeaders().get("Set-Cookie");
        MatcherAssert.assertThat(cookies, hasItem(startsWith("JSESSIONID")));
        MatcherAssert.assertThat(cookies, hasItem(startsWith("X-Uaa-Csrf")));
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
            assertEquals("test banner", webDriver.findElement(By.cssSelector(".login-header span")).getText());
        assertEquals("rgba(68, 68, 68, 1)", webDriver.findElement(By.cssSelector(".login-header")).getCssValue("background-color"));
        assertEquals("rgba(17, 17, 17, 1)", webDriver.findElement(By.cssSelector(".login-header span")).getCssValue("color"));

        String base64Val = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAATBJREFUeNqk008og3Ecx/HNnrJSu63kIC5qKRe7KeUiOSulTHJUTrsr0y5ycFaEgyQXElvt5KDYwU0uO2hSUy4KoR7v7/qsfmjPHvzq1e/XU8/39/3zPFHf9yP/WV7jED24nGRbxDFWUAsToM05zyKFLG60d/wmQBxWzwyOlMU1phELEyCmtPeRQRoVbKOM0VYB6q0QW+3IYQpJFFDEYFCAiMqwNY857Ko3SxjGBTbRXb+xMUamcMbWh148YwJvOHSCdyqTAdxZo72ADGwKT98C9CChcxUPQSVYLz50toae4Fy9WcAISl7AiN/RhS1N5RV5rOLxx5eom90pvGAI/VjHMm6bfspK18a1gXvsqM41XDVL052C1Tim56cYd/rR+mdSrXGluxfm5S8Z/HV9CjAAvQZLXoa5mpgAAAAASUVORK5CYII=";
        banner.setLogo(base64Val);

        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId, config);
        webDriver.get(zoneUrl);

        assertEquals("data:image/png;base64," + base64Val, webDriver.findElement(By.cssSelector(".login-header img")).getAttribute("src"));
        assertEquals(2, webDriver.findElement(By.cssSelector(".login-header")).findElements(By.xpath(".//*")).size());
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
        assertEquals(0, webDriver.findElements(By.cssSelector(".login-header")).size());
    }

    @Test
    public void testSuccessfulLoginNewUser() throws Exception {
        String newUserEmail = createAnotherUser();
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(baseUrl + "/login");
        assertEquals("Cloud Foundry", webDriver.getTitle());
        attemptLogin(newUserEmail, USER_PASSWORD);
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Where to?"));
        webDriver.get(baseUrl + "/logout.do");
        attemptLogin(newUserEmail, USER_PASSWORD);

        assertNotNull(webDriver.findElement(By.cssSelector("#last_login_time")));

        IntegrationTestUtils.validateAccountChooserCookie(baseUrl, webDriver);
    }

    @Test
    public void testNoZoneFound() throws Exception {
        assumeTrue("Expected testzone1/2/3/4/doesnotexist.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());
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
    public void testPasscodeRedirect() throws Exception {
        webDriver.get(baseUrl + "/passcode");
        assertEquals("Cloud Foundry", webDriver.getTitle());

        attemptLogin(testAccounts.getUserName(), testAccounts.getPassword());

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Temporary Authentication Code"));
    }

    @Test
    public void testFailedLogin() throws Exception {
        webDriver.get(baseUrl + "/login");
        assertEquals("Cloud Foundry", webDriver.getTitle());

        attemptLogin(testAccounts.getUserName(), "invalidpassword");

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Welcome!"));
    }

    @Test
    public void testAccessDeniedIfCsrfIsMissing() throws Exception {
        RestTemplate template = new RestTemplate();
        template.setErrorHandler(new ResponseErrorHandler() {
            @Override
            public boolean hasError(ClientHttpResponse response) throws IOException {
                return response.getRawStatusCode() >= 500;
            }

            @Override
            public void handleError(ClientHttpResponse response) throws IOException {
            }

        });
        LinkedMultiValueMap<String,String> body = new LinkedMultiValueMap<>();
        body.add("username", testAccounts.getUserName());
        body.add("password", testAccounts.getPassword());
        HttpHeaders headers = new HttpHeaders();
        headers.add(headers.ACCEPT, MediaType.TEXT_HTML_VALUE);
        ResponseEntity<String> loginResponse = template.exchange(baseUrl + "/login.do",
            HttpMethod.POST,
            new HttpEntity<>(body, headers),
            String.class);
        assertEquals(HttpStatus.FORBIDDEN, loginResponse.getStatusCode());
        assertTrue("CSRF message should be shown", loginResponse.getBody().contains("Invalid login attempt, request does not meet our security standards, please try again."));
    }

    @Test
    public void testCsrfIsResetDuringLoginPageReload() {
        webDriver.get(baseUrl + "/login");
        String csrf1 = webDriver.manage().getCookieNamed(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME).getValue();
        webDriver.get(baseUrl + "/login");
        String csrf2 = webDriver.manage().getCookieNamed(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME).getValue();
        assertNotEquals(csrf1, csrf2);
    }

    @Test
    public void testRedirectAfterFailedLogin() throws Exception {
        RestTemplate template = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.set(headers.ACCEPT, MediaType.TEXT_HTML_VALUE);
        ResponseEntity<String> loginResponse = template.exchange(baseUrl + "/login",
            HttpMethod.GET,
            new HttpEntity<>(null, headers),
            String.class);

        if (loginResponse.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : loginResponse.getHeaders().get("Set-Cookie")) {
                headers.add("Cookie", cookie);
            }
        }
        String csrf = IntegrationTestUtils.extractCookieCsrf(loginResponse.getBody());
        LinkedMultiValueMap<String,String> body = new LinkedMultiValueMap<>();
        body.add("username", testAccounts.getUserName());
        body.add("password", "invalidpassword");
        body.add(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, csrf);
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
    public void userLockedoutAfterFailedAttempts() throws Exception {
        String userEmail = createAnotherUser();

        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(baseUrl + "/login");

        for (int i = 0; i < 5; i++) {
            attemptLogin(userEmail, "invalidpassword");
        }

        attemptLogin(userEmail, USER_PASSWORD);
        assertThat(webDriver.findElement(By.cssSelector(".alert-error")).getText(), Matchers.containsString("Your account has been locked because of too many failed attempts to login."));
    }

    public void attemptLogin(String username, String password) {
        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.findElement(By.name("password")).sendKeys(password);
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
    }

    @Test
    public void testBuildInfo() throws Exception {
        webDriver.get(baseUrl + "/login");

        String regex = "Version: \\S+, Commit: \\w{7}, Timestamp: .+, UAA: " + baseUrl;
        assertTrue(webDriver.findElement(By.cssSelector(".footer .copyright")).getAttribute("title").matches(regex));
    }

    @Test
    public void testAccountChooserManualLogin() throws Exception {
        String zoneUrl = createDiscoveryZone();

        String userEmail = createAnotherUser(zoneUrl);
        webDriver.get(zoneUrl + "/logout");
        webDriver.manage().deleteAllCookies();
        webDriver.get(zoneUrl);

        loginThroughDiscovery(userEmail, USER_PASSWORD);
        webDriver.get(zoneUrl + "/logout");

        webDriver.get(zoneUrl);
        assertEquals("Sign in to another account", webDriver.findElement(By.cssSelector("div.action a")).getText());
        webDriver.findElement(By.cssSelector("div.action a")).click();

        loginThroughDiscovery(userEmail, USER_PASSWORD);
        assertEquals("Where to?", webDriver.findElement(By.cssSelector(".island h1")).getText());
    }

    @Test
    public void testAccountChooserFlow() throws Exception {
        String zoneUrl = createDiscoveryZone();

        String userEmail = createAnotherUser(zoneUrl);
        webDriver.get(zoneUrl + "/logout");
        webDriver.get(zoneUrl);

        loginThroughDiscovery(userEmail, USER_PASSWORD);
        webDriver.get(zoneUrl + "/logout");

        webDriver.get(zoneUrl);
        assertEquals(userEmail, webDriver.findElement(By.className("email-address")).getText());
        webDriver.findElement(By.className("email-address")).click();

        assertEquals(userEmail, webDriver.findElement(By.id("username")).getAttribute("value"));
        webDriver.findElement(By.id("password")).sendKeys(USER_PASSWORD);
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
        assertEquals("Where to?", webDriver.findElement(By.cssSelector(".island h1")).getText());
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
    }

    @Test
    public void testLoginReloadRetainsFormRedirect() {

        String redirectUri = "http://expected.com";
        webDriver.get(baseUrl + "/oauth/authorize?client_id=test&redirect_uri="+redirectUri);
        ((JavascriptExecutor)webDriver).executeScript("document.getElementsByName('X-Uaa-Csrf')[0].value=''");
        webDriver.manage().deleteCookieNamed("JSESSIONID");

        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        assertThat(webDriver.getCurrentUrl(), Matchers.containsString("/login"));
        assertThat(webDriver.findElement(By.name("form_redirect_uri")).getAttribute("value"), Matchers.containsString("redirect_uri="+redirectUri));

    }

    private String createAnotherUser() {
        return createAnotherUser(baseUrl);
    }

    private String createAnotherUser(String url) {
        return IntegrationTestUtils.createAnotherUser(webDriver, USER_PASSWORD, simpleSmtpServer, url, testClient);
    }

    private String createDiscoveryZone() {
        testzone3 = "testzone3";

        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        config.setAccountChooserEnabled(true);
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, testzone3, testzone3, config);
        String res = baseUrl.replace("localhost", testzone3 +".localhost");
        webDriver.get(res + "/logout.do");
        webDriver.manage().deleteAllCookies();
        return res;
    }

    private void createZoneAdmin() {
        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
        //TODO add zone admin client here, return it
    }

    private void loginThroughDiscovery(String userEmail, String password) {
        webDriver.findElement(By.id("email")).sendKeys(userEmail);
        webDriver.findElement(By.cssSelector(".form-group input[value='Next']")).click();
        webDriver.findElement(By.id("password")).sendKeys(password);
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
    }
}
