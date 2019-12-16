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
import org.cloudfoundry.identity.uaa.login.test.UnlessProfileActive;
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
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.RestTemplate;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.Iterator;

import static org.apache.commons.lang3.StringUtils.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
@UnlessProfileActive(values = "saml")
public class ResetPasswordIT {

    @Autowired @Rule
    public IntegrationTestRule integrationTestRule;

    @Autowired
    WebDriver webDriver;

    @Autowired
    SimpleSmtpServer simpleSmtpServer;

    @Autowired
    TestClient testClient;

    @Autowired
    RestTemplate restTemplate;

    @Value("${integration.test.base_url}")
    String baseUrl;

    private String username;
    private String email;

    private String scimClientId;
    private String authCodeClientId;

    @Before
    @After
    public void logoutAndClearCookies() {
        try {
            webDriver.get(baseUrl + "/logout.do");
        } catch (org.openqa.selenium.TimeoutException x) {
            //try again - this should not be happening - 20 second timeouts
            webDriver.get(baseUrl + "/logout.do");
        }
        webDriver.manage().deleteAllCookies();
    }

    @Before
    public void setUp() {
        SecureRandom secureRandom = new SecureRandom();

        scimClientId = "scim" + secureRandom.nextInt();
        authCodeClientId = "auth_code_" + secureRandom.nextInt();
        username = "user" + secureRandom.nextInt();
        email = username + "@example.com";

        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");
        testClient.createScimClient(adminAccessToken, scimClientId);
        BaseClientDetails authCodeClient = new BaseClientDetails(authCodeClientId, "oauth", "uaa.user", "authorization_code,refresh_token", null, "http://example.redirect.com");
        authCodeClient.setClientSecret("scimsecret");
        authCodeClient.setAutoApproveScopes(Collections.singletonList("uaa.user"));
        IntegrationTestUtils.createClient(adminAccessToken, baseUrl, authCodeClient);
        String scimAccessToken = testClient.getOAuthAccessToken(scimClientId, "scimsecret", "client_credentials", "scim.read scim.write password.write");
        testClient.createUser(scimAccessToken, username, email, "secr3T", true);
    }

    @After
    public void tearDown() {
        webDriver.get(baseUrl + "/logout.do");
    }

    @Test
    public void resettingAPasswordWithUsername() {
        beginPasswordReset(username);
        finishPasswordReset(username, email);
    }

    @Test
    public void resettingAPasswordWithPrimaryEmail() {
        int receivedEmailSize = simpleSmtpServer.getReceivedEmailSize();

        beginPasswordReset(email);

        assertEquals(receivedEmailSize, simpleSmtpServer.getReceivedEmailSize());
    }

    @Test
    public void resetPassword_with_clientRedirect() {
        webDriver.get(baseUrl + "/forgot_password?client_id=" + scimClientId + "&redirect_uri=http://example.redirect.com");
        Assert.assertEquals("Reset Password", webDriver.findElement(By.tagName("h1")).getText());

        int receivedEmailSize = simpleSmtpServer.getReceivedEmailSize();

        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.findElement(By.xpath("//input[@value='Send reset password link']")).click();
        Assert.assertEquals("Instructions Sent", webDriver.findElement(By.tagName("h1")).getText());

        assertEquals(receivedEmailSize + 1, simpleSmtpServer.getReceivedEmailSize());
        Iterator receivedEmail = simpleSmtpServer.getReceivedEmail();
        SmtpMessage message = (SmtpMessage) receivedEmail.next();
        receivedEmail.remove();
        assertEquals(email, message.getHeaderValue("To"));
        assertThat(message.getBody(), containsString("Reset your password"));

        Assert.assertEquals("Please check your email for a reset password link.", webDriver.findElement(By.cssSelector(".instructions-sent")).getText());

        // Click link in email
        String link = testClient.extractLink(message.getBody());
        assertFalse(contains(link, "@"));
        assertFalse(contains(link, "%40"));
        webDriver.get(link);

        webDriver.findElement(By.name("password")).sendKeys("new_password");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("new_password");
        webDriver.findElement(By.xpath("//input[@value='Create new password']")).click();

        assertEquals(baseUrl + "/login?success=password_reset&form_redirect_uri=http://example.redirect.com", webDriver.getCurrentUrl());
    }

    @Test
    public void testNotAutoLoginAfterResetPassword() {
        webDriver.get(baseUrl + "/oauth/authorize?client_id=" + authCodeClientId + "&redirect_uri=http://example.redirect.com&grant_type=authorization_code&response_type=code");
//        webDriver.get();
        webDriver.findElement(By.linkText("Reset password")).click();
        Assert.assertEquals("Reset Password", webDriver.findElement(By.tagName("h1")).getText());

        int receivedEmailSize = simpleSmtpServer.getReceivedEmailSize();

        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.findElement(By.xpath("//input[@value='Send reset password link']")).click();
        Assert.assertEquals("Instructions Sent", webDriver.findElement(By.tagName("h1")).getText());

        assertEquals(receivedEmailSize + 1, simpleSmtpServer.getReceivedEmailSize());
        Iterator receivedEmail = simpleSmtpServer.getReceivedEmail();
        SmtpMessage message = (SmtpMessage) receivedEmail.next();
        receivedEmail.remove();
        assertEquals(email, message.getHeaderValue("To"));
        assertThat(message.getBody(), containsString("Reset your password"));

        Assert.assertEquals("Please check your email for a reset password link.", webDriver.findElement(By.cssSelector(".instructions-sent")).getText());

        // Click link in email
        String link = testClient.extractLink(message.getBody());
        assertFalse(contains(link, "@"));
        assertFalse(contains(link, "%40"));
        webDriver.get(link);

        webDriver.findElement(By.name("password")).sendKeys("new_password");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("new_password");
        webDriver.findElement(By.xpath("//input[@value='Create new password']")).click();

        assertEquals(baseUrl + "/login?success=password_reset", webDriver.getCurrentUrl());
        assertThat(webDriver.findElement(By.cssSelector(".alert-success")).getText(), containsString("Password reset successful"));
        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.findElement(By.name("password")).sendKeys("new_password");
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        assertThat(webDriver.getCurrentUrl(), startsWith("http://example.redirect.com/?code="));
    }

    @Test
    public void resettingAPasswordForANonExistentUser() {
        int receivedEmailSize = simpleSmtpServer.getReceivedEmailSize();

        beginPasswordReset("nonexistent_user");

        assertEquals(receivedEmailSize, simpleSmtpServer.getReceivedEmailSize());
    }

    @Test
    public void resettingAPasswordWithInvalidPassword() {
        // Go to Forgot Password page
        beginPasswordReset(username);
        String link = getPasswordResetLink(email);
        webDriver.get(link);

        // Enter invalid password information
        webDriver.findElement(By.name("password")).sendKeys("newsecret");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("");
        webDriver.findElement(By.xpath("//input[@value='Create new password']")).click();
        assertThat(webDriver.findElement(By.cssSelector(".error-message")).getText(), containsString("Passwords must match and not be empty."));
    }

    @Test
    public void codesCanOnlyBeUsedOnce() {
        // Go to Forgot Password page
        beginPasswordReset(username);
        String link = getPasswordResetLink(email);
        webDriver.get(link);

        // Attempt to use same code again
        webDriver.get(link);

        assertThat(webDriver.findElement(By.cssSelector(".error-message")).getText(), containsString("Sorry, your reset password link is no longer valid. You can request another one below."));
    }

    @Test
    public void resetPassword_displaysErrorMessage_WhenPasswordIsInvalid() {
        String newPassword = new RandomValueStringGenerator(260).generate();
        beginPasswordReset(username);

        String link = getPasswordResetLink(email);
        webDriver.get(link);

        webDriver.findElement(By.name("password")).sendKeys(newPassword);
        webDriver.findElement(By.name("password_confirmation")).sendKeys(newPassword);
        webDriver.findElement(By.xpath("//input[@value='Create new password']")).click();
        assertThat(webDriver.findElement(By.cssSelector(".error-message")).getText(), containsString("Password must be no more than 255 characters in length."));
    }

    @Test
    public void resetPassword_displaysErrorMessage_NewPasswordSameAsOld() {
        beginPasswordReset(username);
        String link = getPasswordResetLink(email);
        webDriver.get(link);

        webDriver.findElement(By.name("password")).sendKeys("secr3T");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("secr3T");
        webDriver.findElement(By.xpath("//input[@value='Create new password']")).click();
        assertThat(webDriver.findElement(By.cssSelector(".error-message")).getText(), containsString("Your new password cannot be the same as the old password."));
    }

    private void beginPasswordReset(String username) {
        webDriver.get(baseUrl + "/login");
        Assert.assertEquals("Cloud Foundry", webDriver.getTitle());
        webDriver.findElement(By.linkText("Reset password")).click();
        Assert.assertEquals("Reset Password", webDriver.findElement(By.tagName("h1")).getText());

        // Enter email address
        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.findElement(By.xpath("//input[@value='Send reset password link']")).click();
        Assert.assertEquals("Instructions Sent", webDriver.findElement(By.tagName("h1")).getText());
    }

    private String getPasswordResetLink(String email) {
        Iterator receivedEmail = simpleSmtpServer.getReceivedEmail();
        SmtpMessage message = (SmtpMessage) receivedEmail.next();
        receivedEmail.remove();
        assertEquals(email, message.getHeaderValue("To"));
        assertThat(message.getBody(), containsString("Reset your password"));

        Assert.assertEquals("Please check your email for a reset password link.", webDriver.findElement(By.cssSelector(".instructions-sent")).getText());

        // Extract link from email
        return testClient.extractLink(message.getBody());
    }

    private void finishPasswordReset(String username, String email) {
        String link = getPasswordResetLink(email);
        webDriver.get(link);

        // Successfully choose password
        webDriver.findElement(By.name("password")).sendKeys("newsecr3T");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("newsecr3T");
        webDriver.findElement(By.xpath("//input[@value='Create new password']")).click();
        assertThat(webDriver.getCurrentUrl(), is(baseUrl + "/login?success=password_reset"));

        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.findElement(By.name("password")).sendKeys("newsecr3T");
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), containsString("Where to?"));
    }

}
