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

import com.dumbster.smtp.SimpleSmtpServer;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.client.test.TestAccounts;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.test.UaaWebDriver;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation.Banner;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
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
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.doesSupportZoneDNS;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
class LoginIT {

    private static final String USER_PASSWORD = "sec3Tas";

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
    TestClient testClient;

    @Autowired
    SimpleSmtpServer simpleSmtpServer;

    @BeforeEach
    @AfterEach
    void logout_and_clear_cookies() {
        try {
            webDriver.get(baseUrl + "/logout.do");
        } catch (org.openqa.selenium.TimeoutException x) {
            //try again - this should not be happening - 20 second timeouts
            webDriver.get(baseUrl + "/logout.do");
        }
        webDriver.manage().deleteAllCookies();
    }

    @Test
    void check_JSESSIONID_and_Current_User_Cookies_defaults() {
        RestTemplate template = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        List<String> cookies;
        LinkedMultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("username", testAccounts.getUserName());
        requestBody.add("password", testAccounts.getPassword());

        headers.set(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE);
        ResponseEntity<String> loginResponse = template.exchange(baseUrl + "/login",
                GET,
                new HttpEntity<>(null, headers),
                String.class);

        IntegrationTestUtils.copyCookies(loginResponse, headers);
        String csrf = IntegrationTestUtils.extractCookieCsrf(loginResponse.getBody());
        requestBody.add(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, csrf);

        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        loginResponse = template.exchange(baseUrl + "/login.do",
                POST,
                new HttpEntity<>(requestBody, headers),
                String.class);
        cookies = loginResponse.getHeaders().get("Set-Cookie");
        assertThat(cookies).anySatisfy(s -> assertThat(s).startsWith("JSESSIONID"))
                .anySatisfy(s -> assertThat(s).startsWith("X-Uaa-Csrf"))
                .anySatisfy(s -> assertThat(s).startsWith("Current-User"));
        headers.clear();
        boolean jsessionIdValidated = false;
        for (String cookie : loginResponse.getHeaders().get("Set-Cookie")) {
            if (cookie.contains("JSESSIONID")) {
                jsessionIdValidated = true;
                assertThat(cookie).contains("HttpOnly")
                        .contains("SameSite=None")
                        .contains("Secure");
            }
            if (cookie.contains("Current-User")) {
                assertThat(cookie).contains("SameSite=Strict");
            }
        }
        assertThat(jsessionIdValidated).as("Did not find JSESSIONID").isTrue();
    }

    @Test
    void bannerFunctionalityInDiscoveryPage() {
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

        String zoneUrl = baseUrl.replace("localhost", zoneId + ".localhost");
        webDriver.get(zoneUrl);
        webDriver.manage().deleteAllCookies();
        webDriver.navigate().refresh();
        assertThat(webDriver.findElement(By.cssSelector(".banner-header span")).getText()).isEqualTo("test banner");
        assertThat(webDriver.findElement(By.cssSelector(".banner-header")).getCssValue("background-color")).isEqualTo("rgba(68, 68, 68, 1)");
        assertThat(webDriver.findElement(By.cssSelector(".banner-header span")).getCssValue("color")).isEqualTo("rgba(17, 17, 17, 1)");

        String base64Val = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAATBJREFUeNqk008og3Ecx/HNnrJSu63kIC5qKRe7KeUiOSulTHJUTrsr0y5ycFaEgyQXElvt5KDYwU0uO2hSUy4KoR7v7/qsfmjPHvzq1e/XU8/39/3zPFHf9yP/WV7jED24nGRbxDFWUAsToM05zyKFLG60d/wmQBxWzwyOlMU1phELEyCmtPeRQRoVbKOM0VYB6q0QW+3IYQpJFFDEYFCAiMqwNY857Ko3SxjGBTbRXb+xMUamcMbWh148YwJvOHSCdyqTAdxZo72ADGwKT98C9CChcxUPQSVYLz50toae4Fy9WcAISl7AiN/RhS1N5RV5rOLxx5eom90pvGAI/VjHMm6bfspK18a1gXvsqM41XDVL052C1Tim56cYd/rR+mdSrXGluxfm5S8Z/HV9CjAAvQZLXoa5mpgAAAAASUVORK5CYII=";
        banner.setLogo(base64Val);

        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId, config);
        webDriver.get(zoneUrl);

        assertThat(webDriver.findElement(By.cssSelector(".banner-header img")).getAttribute("src")).isEqualTo("data:image/png;base64," + base64Val);
        assertThat(webDriver.findElement(By.cssSelector(".banner-header")).findElements(By.xpath(".//*"))).hasSize(2);
    }

    @Test
    void bannerBackgroundIsHiddenIfNoTextOrImage() {
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

        String zoneUrl = baseUrl.replace("localhost", zoneId + ".localhost");
        webDriver.get(zoneUrl);
        webDriver.manage().deleteAllCookies();
        webDriver.navigate().refresh();
        assertThat(webDriver.findElements(By.cssSelector(".banner-header"))).isEmpty();
    }

    @Test
    void successfulLoginNewUser() {
        String newUserEmail = createAnotherUser();
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(baseUrl + "/login");
        assertThat(webDriver.getTitle()).isEqualTo("Cloud Foundry");
        attemptLogin(newUserEmail, USER_PASSWORD);
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Where to?");
        webDriver.get(baseUrl + "/logout.do");
        attemptLogin(newUserEmail, USER_PASSWORD);

        assertThat(webDriver.findElement(By.cssSelector("#last_login_time"))).isNotNull();
        String lastLoginDate = webDriver.findElement(By.cssSelector("#last_login_time")).getAttribute("innerHTML");
        assertThat(lastLoginDate).isNotEmpty();

        IntegrationTestUtils.validateAccountChooserCookie(baseUrl, webDriver, IdentityZoneHolder.get());
    }

    @Test
    void loginHint() {
        String newUserEmail = createAnotherUser();
        webDriver.get(baseUrl + "/logout.do");
        String ldapLoginHint = URLEncoder.encode("{\"origin\":\"ldap\"}", StandardCharsets.UTF_8);
        webDriver.get(baseUrl + "/login?login_hint=" + ldapLoginHint);
        assertThat(webDriver.getTitle()).isEqualTo("Cloud Foundry");
        assertThat(webDriver.getPageSource()).doesNotContain("or sign in with:");
        attemptLogin(newUserEmail, USER_PASSWORD);
        assertThat(webDriver.findElement(By.className("alert-error")).getText()).contains("Provided credentials are invalid. Please try again.");

        String uaaLoginHint = URLEncoder.encode("{\"origin\":\"uaa\"}", StandardCharsets.UTF_8);
        webDriver.get(baseUrl + "/login?login_hint=" + uaaLoginHint);
        assertThat(webDriver.getTitle()).isEqualTo("Cloud Foundry");
        assertThat(webDriver.getPageSource()).doesNotContain("or sign in with:");
        attemptLogin(newUserEmail, USER_PASSWORD);
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Where to?");
        webDriver.get(baseUrl + "/logout.do");
    }

    @Test
    void noZoneFound() {
        assertThat(doesSupportZoneDNS()).as("Expected testzone1/2/3/4/doesnotexist.localhost to resolve to 127.0.0.1").isTrue();
        webDriver.get(baseUrl.replace("localhost", "testzonedoesnotexist.localhost") + "/login");
        assertThat(webDriver.findElement(By.tagName("p")).getText()).isEqualTo("The subdomain does not map to a valid identity zone.");
    }

    @Test
    void autocompleteIsDisabledForPasswordField() {
        webDriver.get(baseUrl + "/login");
        WebElement password = webDriver.findElement(By.name("password"));
        assertThat(password.getAttribute("autocomplete")).isEqualTo("off");
    }

    @Test
    void passcodeRedirect() {
        webDriver.get(baseUrl + "/passcode");
        assertThat(webDriver.getTitle()).isEqualTo("Cloud Foundry");

        attemptLogin(testAccounts.getUserName(), testAccounts.getPassword());

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Temporary Authentication Code");

        // Verify that the CopyToClipboard function can be executed
        String passcode = webDriver.findElement(By.id("passcode")).getText();
        (webDriver.getJavascriptExecutor()).executeScript("CopyToClipboard",
                passcode);
        // Verify that the copybutton can be clicked
        webDriver.findElement(By.id("copybutton")).click();
    }

    @Test
    void unsuccessfulLogin() {
        webDriver.get(baseUrl + "/login");
        assertThat(webDriver.getTitle()).isEqualTo("Cloud Foundry");

        attemptLogin(testAccounts.getUserName(), "invalidpassword");

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Welcome!");
    }

    @Test
    void accessDeniedIfCsrfIsMissing() {
        RestTemplate template = new RestTemplate();
        template.setErrorHandler(new ResponseErrorHandler() {
            @Override
            public boolean hasError(ClientHttpResponse response) throws IOException {
                return response.getStatusCode().is5xxServerError();
            }

            @Override
            public void handleError(ClientHttpResponse response) {
                // pass through
            }
        });
        LinkedMultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("username", testAccounts.getUserName());
        body.add("password", testAccounts.getPassword());
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE);
        ResponseEntity<String> loginResponse = template.exchange(baseUrl + "/login.do",
                HttpMethod.POST,
                new HttpEntity<>(body, headers),
                String.class);
        assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(loginResponse.getHeaders().getFirst("Location")).contains("invalid_login_request");
    }

    @Test
    void csrfIsResetDuringLoginPageReload() {
        webDriver.get(baseUrl + "/login");
        String csrf1 = webDriver.manage().getCookieNamed(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME).getValue();
        webDriver.get(baseUrl + "/login");
        String csrf2 = webDriver.manage().getCookieNamed(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME).getValue();
        assertThat(csrf2).isNotEqualTo(csrf1);
    }

    @Test
    void redirectAfterUnsuccessfulLogin() {
        RestTemplate template = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE);
        ResponseEntity<String> loginResponse = template.exchange(baseUrl + "/login",
                HttpMethod.GET,
                new HttpEntity<>(null, headers),
                String.class);

        IntegrationTestUtils.copyCookies(loginResponse, headers);
        String csrf = IntegrationTestUtils.extractCookieCsrf(loginResponse.getBody());
        LinkedMultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("username", testAccounts.getUserName());
        body.add("password", "invalidpassword");
        body.add(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, csrf);
        loginResponse = template.exchange(baseUrl + "/login.do",
                HttpMethod.POST,
                new HttpEntity<>(body, headers),
                String.class);
        assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.FOUND);
    }

    @Test
    void loginPageReloadBasedOnCsrf() {
        webDriver.get(baseUrl + "/login");
        assertThat(webDriver.getPageSource()).contains("http-equiv=\"refresh\"");
    }

    @Test
    void userLockedoutAfterUnsuccessfulAttempts() {
        String userEmail = createAnotherUser();

        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(baseUrl + "/login");

        for (int i = 0; i < 5; i++) {
            attemptLogin(userEmail, "invalidpassword");
        }

        attemptLogin(userEmail, USER_PASSWORD);
        assertThat(webDriver.findElement(By.cssSelector(".alert-error")).getText()).contains("Your account has been locked because of too many failed attempts to login.");
    }

    public void attemptLogin(String username, String password) {
        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.findElement(By.name("password")).sendKeys(password);
        webDriver.clickAndWait(By.xpath("//input[@value='Sign in']"));
    }

    @Test
    void buildInfo() {
        webDriver.get(baseUrl + "/login");

        String regex = "Version: \\S+, Commit: \\w{7}, Timestamp: .+, UAA: " + baseUrl;
        assertThat(webDriver.findElement(By.cssSelector(".footer .copyright")).getAttribute("title")).matches(regex);
    }

    @Test
    void accountChooserManualLogin() {
        String zoneUrl = createDiscoveryZone();

        String userEmail = createAnotherUser(zoneUrl);
        webDriver.get(zoneUrl + "/logout.do");
        webDriver.manage().deleteAllCookies();
        webDriver.get(zoneUrl);

        loginThroughDiscovery(userEmail, USER_PASSWORD);
        webDriver.get(zoneUrl + "/logout.do");

        webDriver.get(zoneUrl);
        assertThat(webDriver.findElement(By.cssSelector("div.action a")).getText()).isEqualTo("Sign in to another account");
        webDriver.clickAndWait(By.cssSelector("div.action a"));

        loginThroughDiscovery(userEmail, USER_PASSWORD);
        assertThat(webDriver.findElement(By.cssSelector(".island h1")).getText()).isEqualTo("Where to?");
    }

    @Test
    void accountChooserFlow() {
        String zoneUrl = createDiscoveryZone();

        String userEmail = createAnotherUser(zoneUrl);
        webDriver.get(zoneUrl + "/logout.do");
        webDriver.get(zoneUrl);

        loginThroughDiscovery(userEmail, USER_PASSWORD);
        webDriver.get(zoneUrl + "/logout.do");

        webDriver.get(zoneUrl);
        assertThat(webDriver.findElement(By.className("email-address")).getText()).startsWith(userEmail)
                .contains(OriginKeys.UAA);
        webDriver.clickAndWait(By.className("email-address"));

        assertThat(webDriver.findElement(By.id("username")).getAttribute("value")).isEqualTo(userEmail);
        assertThat(webDriver.getCurrentUrl()).contains("login_hint");
        webDriver.findElement(By.id("password")).sendKeys(USER_PASSWORD);
        webDriver.clickAndWait(By.xpath("//input[@value='Sign in']"));
        assertThat(webDriver.findElement(By.cssSelector(".island h1")).getText()).isEqualTo("Where to?");
    }

    @Test
    void accountChooserPopulatesUsernameNotEmailWhenOriginIsUAAorLDAP() throws Exception {
        String userUAA = "{\"userId\":\"1\",\"username\":\"userUAA\",\"origin\":\"uaa\",\"email\":\"user@uaa.org\"}";
        String userLDAP = "{\"userId\":\"2\",\"username\":\"userLDAP\",\"origin\":\"ldap\",\"email\":\"user@ldap.org\"}";
        String userExternal = "{\"userId\":\"3\",\"username\":\"userExternal\",\"origin\":\"external\",\"email\":\"user@external.org\"}";

        String zoneUrl = createDiscoveryZone();
        webDriver.get(zoneUrl);

        webDriver.manage().deleteAllCookies();
        JavascriptExecutor js = webDriver.getJavascriptExecutor();
        js.executeScript("document.cookie = \"Saved-Account-1=" + URLEncoder.encode(userUAA, StandardCharsets.UTF_8.name()) + ";path=/;domain=testzone3.localhost\"");
        js.executeScript("document.cookie = \"Saved-Account-2=" + URLEncoder.encode(userLDAP, StandardCharsets.UTF_8.name()) + ";path=/;domain=testzone3.localhost\"");
        js.executeScript("document.cookie = \"Saved-Account-3=" + URLEncoder.encode(userExternal, StandardCharsets.UTF_8.name()) + ";path=/;domain=testzone3.localhost\"");

        webDriver.navigate().refresh();
        assertThat(webDriver.findElements(By.cssSelector("span.email-address"))).hasSize(3);

        webDriver.clickAndWait(By.xpath("//span[contains(text(), 'userUAA')]"));
        assertThat(webDriver.findElement(By.id("username")).getAttribute("value")).isEqualTo("userUAA");
        webDriver.navigate().back();

        webDriver.clickAndWait(By.xpath("//span[contains(text(), 'userLDAP')]"));
        assertThat(webDriver.findElement(By.id("username")).getAttribute("value")).isEqualTo("userLDAP");
        webDriver.navigate().back();

        webDriver.clickAndWait(By.xpath("//span[contains(text(), 'userExternal')]"));
        assertThat(webDriver.findElement(By.id("username")).getAttribute("value")).isEqualTo("user@external.org");

        webDriver.manage().deleteAllCookies();
    }

    @Test
    void loginReloadRetainsFormRedirect() {

        String redirectUri = "http://expected.com";
        webDriver.get(baseUrl + "/oauth/authorize?client_id=test&redirect_uri=" + redirectUri);
        (webDriver.getJavascriptExecutor()).executeScript("document.getElementsByName('X-Uaa-Csrf')[0].value=''");
        webDriver.manage().deleteCookieNamed("JSESSIONID");

        webDriver.clickAndWait(By.xpath("//input[@value='Sign in']"));

        assertThat(webDriver.getCurrentUrl()).contains("/login");
        assertThat(webDriver.findElement(By.name("form_redirect_uri")).getAttribute("value")).contains("redirect_uri=" + redirectUri);
    }

    private String createAnotherUser() {
        return createAnotherUser(baseUrl);
    }

    private String createAnotherUser(String url) {
        return IntegrationTestUtils.createAnotherUser(webDriver, USER_PASSWORD, simpleSmtpServer, url, testClient);
    }

    private String createDiscoveryZone() {
        String testzone3 = "testzone3";

        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        config.setAccountChooserEnabled(true);
        config.getCorsPolicy().getDefaultConfiguration().setAllowedMethods(
                List.of(GET.toString(), POST.toString()));
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, testzone3, testzone3, config);
        String res = baseUrl.replace("localhost", testzone3 + ".localhost");
        webDriver.get(res + "/logout.do");
        webDriver.manage().deleteAllCookies();
        return res;
    }

    private void loginThroughDiscovery(String userEmail, String password) {
        webDriver.findElement(By.id("email")).sendKeys(userEmail);
        webDriver.clickAndWait(By.cssSelector(".form-group input[value='Next']"));
        webDriver.findElement(By.id("password")).sendKeys(password);
        webDriver.clickAndWait(By.xpath("//input[@value='Sign in']"));
    }
}
