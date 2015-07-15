/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.security.SecureRandom;
import java.util.Iterator;

import static org.apache.commons.lang3.StringUtils.isEmpty;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;

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
    public void setUp() throws Exception {
        webDriver.get(baseUrl + "/logout.do");
    }

    @Test
    public void testSuccessfulLogin() throws Exception {
        webDriver.get(baseUrl + "/login");
        assertEquals("Cloud Foundry", webDriver.getTitle());
        attemptLogin(testAccounts.getUserName(), testAccounts.getPassword());
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Where to?"));
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
    public void testRedirectAfterFailedLogin() throws Exception {
        RestTemplate template = new RestTemplate();
        LinkedMultiValueMap<String,String> body = new LinkedMultiValueMap<>();
        body.add("username", testAccounts.getUserName());
        body.add("password", "invalidpassword");
        ResponseEntity<Void> loginResponse = template.exchange(baseUrl + "/login.do",
            HttpMethod.POST,
            new HttpEntity<>(body, null),
            Void.class);
        assertEquals(HttpStatus.FOUND, loginResponse.getStatusCode());
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
        Assert.assertTrue(webDriver.findElement(By.cssSelector(".footer .copyright")).getAttribute("title").matches(regex));
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
