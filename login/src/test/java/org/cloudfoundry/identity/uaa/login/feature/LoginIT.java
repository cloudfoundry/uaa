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
package org.cloudfoundry.identity.uaa.login.feature;

import com.dumbster.smtp.SimpleSmtpServer;
import com.dumbster.smtp.SmtpMessage;
import org.cloudfoundry.identity.uaa.login.test.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.login.test.IntegrationTestRule;
import org.cloudfoundry.identity.uaa.login.test.TestClient;
import org.hamcrest.Matchers;
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

import java.net.URI;
import java.security.SecureRandom;
import java.util.Iterator;

import static org.apache.commons.lang3.StringUtils.isEmpty;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.springframework.http.HttpStatus.FOUND;

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
    public void setUp() throws Exception {
        webDriver.get(baseUrl + "/logout.do");
    }

    @Test
    public void testSuccessfulLogin() throws Exception {
        webDriver.get(baseUrl + "/login");
        assertEquals("Cloud Foundry", webDriver.getTitle());

        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(testAccounts.getPassword());
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Where to?"));
    }

    @Test
    public void testFailedLogin() throws Exception {
        webDriver.get(baseUrl + "/login");
        assertEquals("Cloud Foundry", webDriver.getTitle());

        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys("invalidpassword");
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

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
    public void testUnverifiedUserLoginResendsVerificationLink() throws Exception {
        String userEmail = createUnverifiedUser();

        webDriver.get(baseUrl + "/oauth/authorize?client_id=app&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fapp&response_type=code&state=6pOfRa");
        assertEquals("Cloud Foundry", webDriver.getTitle());

        int receivedEmailSize = simpleSmtpServer.getReceivedEmailSize();

        webDriver.findElement(By.name("username")).sendKeys(userEmail);
        webDriver.findElement(By.name("password")).sendKeys("secret");
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Welcome!"));
        assertThat(webDriver.findElement(By.cssSelector(".alert-error")).getText(), Matchers.containsString("Your account is not verified"));

        assertEquals(receivedEmailSize + 1, simpleSmtpServer.getReceivedEmailSize());
        Iterator receivedEmail = simpleSmtpServer.getReceivedEmail();
        SmtpMessage message = (SmtpMessage) receivedEmail.next();
        receivedEmail.remove();
        assertEquals(userEmail, message.getHeaderValue("To"));
        assertThat(message.getBody(), containsString("Activate your account"));

        String link = testClient.extractLink(message.getBody());
        assertFalse(isEmpty(link));

        RestTemplate restTemplate = new RestTemplate(new DefaultIntegrationTestConfig.HttpClientFactory());
        ResponseEntity<String> responseEntity = restTemplate.getForEntity(link, String.class);
        assertEquals(FOUND, responseEntity.getStatusCode());
        assertEquals(new URI("http://localhost:8080/app/"), responseEntity.getHeaders().getLocation());
    }

    private String createUnverifiedUser() throws Exception {
        int randomInt = new SecureRandom().nextInt();

        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret");

        String scimClientId = "scim" + randomInt;
        testClient.createScimClient(adminAccessToken, scimClientId);

        String scimAccessToken = testClient.getOAuthAccessToken(scimClientId, "scimsecret", "client_credentials", "scim.read scim.write password.write");

        String userEmail = "user" + randomInt + "@example.com";
        testClient.createUser(scimAccessToken, userEmail, userEmail, "secret", false);

        return userEmail;
    }

    @Test
    public void testBuildInfo() throws Exception {
        webDriver.get(baseUrl + "/login");

        String regex = "Version: \\S+, Commit: \\w{7}, Timestamp: .+, UAA: http://localhost:8080/uaa";
        Assert.assertTrue(webDriver.findElement(By.cssSelector(".footer .copyright")).getAttribute("title").matches(regex));
    }
}
