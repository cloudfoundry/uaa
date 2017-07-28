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
import com.dumbster.smtp.SmtpMessage;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
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
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Iterator;
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
    public void testSuccessfulLoginNewUser() throws Exception {
        String newUserEmail = createAnotherUser();
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(baseUrl + "/login");
        assertEquals("Cloud Foundry", webDriver.getTitle());
        attemptLogin(newUserEmail, "sec3Tas");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Where to?"));
        webDriver.get(baseUrl + "/logout.do");
        attemptLogin(newUserEmail, "sec3Tas");

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

        attemptLogin(userEmail, "sec3Tas");
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

    private String createAnotherUser() {
        String userEmail = "user" + new SecureRandom().nextInt() + "@example.com";

        webDriver.get(baseUrl + "/create_account");
        webDriver.findElement(By.name("email")).sendKeys(userEmail);
        webDriver.findElement(By.name("password")).sendKeys("sec3Tas");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("sec3Tas");
        webDriver.findElement(By.xpath("//input[@value='Send activation link']")).click();

        Iterator receivedEmail = simpleSmtpServer.getReceivedEmail();
        SmtpMessage message = (SmtpMessage) receivedEmail.next();
        receivedEmail.remove();
        webDriver.get(testClient.extractLink(message.getBody()));

        return userEmail;
    }
}
