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
import org.apache.commons.io.FileUtils;
import org.cloudfoundry.identity.uaa.login.test.LoginServerClassRunner;
import org.cloudfoundry.identity.uaa.login.test.UnlessProfileActive;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.web.client.RestTemplate;

import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Iterator;

import static org.apache.commons.lang3.StringUtils.contains;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;

@RunWith(LoginServerClassRunner.class)
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
    private String userEmail;
    private String scimClientId;

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

    @Before
    public void setUp() throws Exception {
        int randomInt = new SecureRandom().nextInt();

        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");
        scimClientId = "scim" + randomInt;
        testClient.createScimClient(adminAccessToken, scimClientId);
        String scimAccessToken = testClient.getOAuthAccessToken(scimClientId, "scimsecret", "client_credentials", "scim.read scim.write password.write");
        username = "user" + randomInt;
        userEmail = username + "@example.com";
        testClient.createUser(scimAccessToken, username, userEmail, "secr3T", true);
    }

    @After
    public void tearDown() throws Exception {
        webDriver.get(baseUrl + "/logout.do");
    }

    @Test
    public void resettingAPassword() throws Exception {

        // Go to Forgot Password page
        String link = beginResetPassword();

        // Enter invalid password information
        webDriver.findElement(By.name("password")).sendKeys("newsecret");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("");
        webDriver.findElement(By.xpath("//input[@value='Create new password']")).click();
        assertThat(webDriver.findElement(By.cssSelector(".error-message")).getText(), containsString("Passwords must match and not be empty."));

        // Successfully choose password
        webDriver.findElement(By.name("password")).sendKeys("newsecr3T");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("newsecr3T");
        webDriver.findElement(By.xpath("//input[@value='Create new password']")).click();
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), containsString("Where to?"));

        // Log out and back in with new password
        webDriver.findElement(By.xpath("//*[text()='"+ username +"']")).click();
        webDriver.findElement(By.linkText("Sign Out")).click();

        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.findElement(By.name("password")).sendKeys("newsecr3T");
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), containsString("Where to?"));

        // Attempt to use same code again
        webDriver.findElement(By.xpath("//*[text()='"+ username +"']")).click();
        webDriver.findElement(By.linkText("Sign Out")).click();

        webDriver.get(link);

        assertThat(webDriver.findElement(By.cssSelector(".error-message")).getText(), containsString("Sorry, your reset password link is no longer valid. You can request another one below."));
    }

    @Test
    public void resetPassword_with_clientRedirect() throws Exception {
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
        assertEquals(userEmail, message.getHeaderValue("To"));
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

        assertEquals("http://example.redirect.com/", webDriver.getCurrentUrl());
    }

    @Test
    public void resettingAPasswordForANonExistentUser() throws Exception {
        webDriver.get(baseUrl + "/login");
        Assert.assertEquals("Cloud Foundry", webDriver.getTitle());

        webDriver.findElement(By.linkText("Reset password")).click();

        Assert.assertEquals("Reset Password", webDriver.findElement(By.tagName("h1")).getText());

        int receivedEmailSize = simpleSmtpServer.getReceivedEmailSize();

        webDriver.findElement(By.name("username")).sendKeys("nonexistent_user");
        webDriver.findElement(By.xpath("//input[@value='Send reset password link']")).click();

        Assert.assertEquals("Instructions Sent", webDriver.findElement(By.tagName("h1")).getText());

        assertEquals(receivedEmailSize, simpleSmtpServer.getReceivedEmailSize());
    }

    @Test
    public void resetPassword_displaysErrorMessage_WhenPasswordIsInvalid() throws Exception {
        String newPassword = new RandomValueStringGenerator(260).generate();
        beginResetPassword();
        webDriver.findElement(By.name("password")).sendKeys(newPassword);
        webDriver.findElement(By.name("password_confirmation")).sendKeys(newPassword);
        webDriver.findElement(By.xpath("//input[@value='Create new password']")).click();
        assertThat(webDriver.findElement(By.cssSelector(".error-message")).getText(), containsString("Password must be no more than 255 characters in length."));
    }

    @Test
    public void resetPassword_displaysErrorMessage_NewPasswordSameAsOld() throws Exception {
        beginResetPassword();
        webDriver.findElement(By.name("password")).sendKeys("secr3T");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("secr3T");
        webDriver.findElement(By.xpath("//input[@value='Create new password']")).click();
        assertThat(webDriver.findElement(By.cssSelector(".error-message")).getText(), containsString("Your new password cannot be the same as the old password."));
    }

    public void takeScreenShot() throws IOException {
        File scrFile = ((TakesScreenshot)webDriver).getScreenshotAs(OutputType.FILE);
        File destFile = new File("testscreenshot-" + System.currentTimeMillis() + ".png");
        FileUtils.copyFile(scrFile, destFile);
        System.out.println("Screenshot in : " + destFile.getAbsolutePath());
    }

    private String beginResetPassword() {
        webDriver.get(baseUrl + "/login");
        Assert.assertEquals("Cloud Foundry", webDriver.getTitle());
        webDriver.findElement(By.linkText("Reset password")).click();
        Assert.assertEquals("Reset Password", webDriver.findElement(By.tagName("h1")).getText());

        // Enter an email address
        int receivedEmailSize = simpleSmtpServer.getReceivedEmailSize();
        webDriver.findElement(By.name("username")).sendKeys(userEmail);
        webDriver.findElement(By.xpath("//input[@value='Send reset password link']")).click();
        //verify no email was sent.
        assertEquals(receivedEmailSize, simpleSmtpServer.getReceivedEmailSize());
        
        webDriver.get(baseUrl + "/login");
        Assert.assertEquals("Cloud Foundry", webDriver.getTitle());
        webDriver.findElement(By.linkText("Reset password")).click();
        Assert.assertEquals("Reset Password", webDriver.findElement(By.tagName("h1")).getText());

        // Successfully enter email address
        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.findElement(By.xpath("//input[@value='Send reset password link']")).click();
        Assert.assertEquals("Instructions Sent", webDriver.findElement(By.tagName("h1")).getText());

        // Check email
        assertEquals(receivedEmailSize + 1, simpleSmtpServer.getReceivedEmailSize());
        Iterator receivedEmail = simpleSmtpServer.getReceivedEmail();
        SmtpMessage message = (SmtpMessage) receivedEmail.next();
        receivedEmail.remove();
        assertEquals(userEmail, message.getHeaderValue("To"));
        assertThat(message.getBody(), containsString("Reset your password"));

        Assert.assertEquals("Please check your email for a reset password link.", webDriver.findElement(By.cssSelector(".instructions-sent")).getText());

        // Click link in email
        String link = testClient.extractLink(message.getBody());
        webDriver.get(link);
        return link;
    }
}
