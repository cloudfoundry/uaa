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
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.login.test.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.login.test.IntegrationTestRule;
import org.cloudfoundry.identity.uaa.login.test.TestClient;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
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
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.RestTemplate;

import java.security.SecureRandom;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Iterator;
import java.util.concurrent.TimeUnit;

import static junit.framework.TestCase.assertNotNull;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.*;
import static org.junit.Assert.assertEquals;
import static org.springframework.http.HttpStatus.FOUND;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class InvitationsIT {

    @Autowired
    TestAccounts testAccounts;
    
    @Autowired @Rule
    public IntegrationTestRule integrationTestRule;

    @Autowired
    WebDriver webDriver;

    @Autowired
    SimpleSmtpServer simpleSmtpServer;

    @Autowired
    TestClient testClient;

    @Value("${integration.test.uaa_url}")
    String uaaUrl;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Value("${integration.test.app_url}")
    String appUrl;

    @Test
    public void testSendInvite() throws Exception {
        int randomInt = new SecureRandom().nextInt();
        String userEmail = "user" + randomInt + "@example.com";
        int receivedEmailSize = simpleSmtpServer.getReceivedEmailSize();

        signIn(testAccounts.getUserName(), testAccounts.getPassword());

        webDriver.findElement(By.linkText("Invite Users")).click();
        assertEquals("Send an invite", webDriver.findElement(By.tagName("h1")).getText());

        webDriver.findElement(By.name("email")).sendKeys(userEmail);
        webDriver.findElement(By.xpath("//input[@value='Send invite']")).click();

        assertEquals("Invite sent", webDriver.findElement(By.tagName("h1")).getText());

        assertEquals(receivedEmailSize + 1, simpleSmtpServer.getReceivedEmailSize());
        Iterator receivedEmail = simpleSmtpServer.getReceivedEmail();
        SmtpMessage message = (SmtpMessage) receivedEmail.next();
        receivedEmail.remove();
        assertEquals(userEmail, message.getHeaderValue("To"));
        assertThat(message.getBody(), containsString("Accept Invite"));

        String link = testClient.extractLink(message.getBody());
        assertTrue(link.contains("/invitations/accept"));
        webDriver.get(link);

        assertEquals("Create your account", webDriver.findElement(By.tagName("h1")).getText());

        webDriver.findElement(By.name("password")).sendKeys("secret");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("secret");

        webDriver.findElement(By.xpath("//input[@value='Create account']")).click();

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), containsString("Where to?"));

        webDriver.findElement(By.xpath("//*[text()='"+userEmail+"']")).click();
        webDriver.findElement(By.linkText("Sign Out")).click();

        webDriver.findElement(By.name("username")).sendKeys(userEmail);
        webDriver.findElement(By.name("password")).sendKeys("secret");
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), containsString("Where to?"));
    }

    @Test
    public void testClientRedirectInviteUser() throws Exception {
        String code = generateCode();
        webDriver.get(baseUrl + "/invitations/accept?code=" + code);
        assertEquals("Create your account", webDriver.findElement(By.tagName("h1")).getText());

        webDriver.findElement(By.name("password")).sendKeys("secret");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("secret");

        webDriver.findElement(By.xpath("//input[@value='Create account']")).click();
        Assert.assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), not(containsString("Where to?")));
    }

    private String generateCode() {
        String token = testClient.getOAuthAccessToken("login", "loginsecret", "client_credentials", "password.write,scim.write");
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + token);
        RestTemplate uaaTemplate = new RestTemplate();

        String userEmail = "user" + new SecureRandom().nextInt() + "@example.com";
        ScimUser scimUser = new ScimUser();
        scimUser.setUserName(userEmail);
        ScimUser.Email email = new ScimUser.Email();
        email.setPrimary(true);
        email.setValue(userEmail);
        scimUser.setEmails(Arrays.asList(email));
        scimUser.setOrigin(Origin.UAA);

        HttpEntity<ScimUser> request = new HttpEntity<>(scimUser, headers);
        ResponseEntity<ScimUser> response = uaaTemplate.exchange(uaaUrl + "/Users", HttpMethod.POST, request, ScimUser.class);

        Timestamp expiry = new Timestamp(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(System.currentTimeMillis() + 24 * 3600, TimeUnit.MILLISECONDS));
        ExpiringCode expiringCode = new ExpiringCode(null, expiry, "{\"client_id\":\"app\", \"user_id\":\"" + response.getBody().getId() + "\", \"email\":\"user@example.com\"}");
        HttpEntity<ExpiringCode> expiringCodeRequest = new HttpEntity<>(expiringCode, headers);
        ResponseEntity<ExpiringCode> expiringCodeResponse = uaaTemplate.exchange(uaaUrl + "/Codes", HttpMethod.POST, expiringCodeRequest, ExpiringCode.class);
        expiringCode = expiringCodeResponse.getBody();
        return expiringCode.getCode();
    }


    private void signIn(String userName, String password) {
        webDriver.get(baseUrl + "/login");
        webDriver.findElement(By.name("username")).sendKeys(userName);
        webDriver.findElement(By.name("password")).sendKeys(password);
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), containsString("Where to?"));
    }
}
