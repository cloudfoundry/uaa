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

import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Iterator;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
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
import org.springframework.test.context.ContextConfiguration;
import org.springframework.web.client.RestTemplate;

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

    private String userEmail;

    @Before
    public void setUp() throws Exception {
        int randomInt = new SecureRandom().nextInt();

        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret");
        String scimClientId = "scim" + randomInt;
        testClient.createScimClient(adminAccessToken, scimClientId);
        String scimAccessToken = testClient.getOAuthAccessToken(scimClientId, "scimsecret", "client_credentials", "scim.read scim.write password.write");
        userEmail = "user" + randomInt + "@example.com";
        testClient.createUser(scimAccessToken, userEmail, userEmail, "secret", true);
        webDriver.get(baseUrl + "/logout.do");
    }

    @After
    public void tearDown() throws Exception {
        webDriver.get(baseUrl + "/logout.do");
    }

    @Test
    public void resettingAPassword() throws Exception {

        // Go to Forgot Password page
        webDriver.get(baseUrl + "/login");
        Assert.assertEquals("Cloud Foundry", webDriver.getTitle());
        webDriver.findElement(By.linkText("Reset password")).click();
        Assert.assertEquals("Reset Password", webDriver.findElement(By.tagName("h1")).getText());

        // Enter an invalid email address
        webDriver.findElement(By.name("email")).sendKeys("notAnEmail");
        webDriver.findElement(By.xpath("//input[@value='Send reset password link']")).click();
        assertThat(webDriver.findElement(By.className("error-message")).getText(), Matchers.equalTo("Please enter a valid email address."));

        // Successfully enter email address
        int receivedEmailSize = simpleSmtpServer.getReceivedEmailSize();

        webDriver.findElement(By.name("email")).sendKeys(userEmail);
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

        // Enter invalid password information
        webDriver.findElement(By.name("password")).sendKeys("newsecret");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("");
        webDriver.findElement(By.xpath("//input[@value='Create new password']")).click();
        assertThat(webDriver.findElement(By.cssSelector(".error-message")).getText(), containsString("Passwords must match and not be empty."));

        // Successfully choose password
        webDriver.findElement(By.name("password")).sendKeys("newsecret");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("newsecret");
        webDriver.findElement(By.xpath("//input[@value='Create new password']")).click();
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), containsString("Where to?"));

        // Log out and back in with new password
        webDriver.findElement(By.xpath("//*[text()='"+userEmail+"']")).click();
        webDriver.findElement(By.linkText("Sign Out")).click();

        webDriver.findElement(By.name("username")).sendKeys(userEmail);
        webDriver.findElement(By.name("password")).sendKeys("newsecret");
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), containsString("Where to?"));

        // Attempt to use same code again
        webDriver.findElement(By.xpath("//*[text()='"+userEmail+"']")).click();
        webDriver.findElement(By.linkText("Sign Out")).click();

        webDriver.get(link);

        webDriver.findElement(By.name("password")).sendKeys("newsecret");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("newsecret");
        webDriver.findElement(By.xpath("//input[@value='Create new password']")).click();

        assertThat(webDriver.findElement(By.cssSelector(".error-message")).getText(), containsString("Sorry, your reset password link is no longer valid. You can request another one below."));
    }

    @Test
    public void resettingAPasswordForANonExistentUser() throws Exception {
        webDriver.get(baseUrl + "/login");
        Assert.assertEquals("Cloud Foundry", webDriver.getTitle());

        webDriver.findElement(By.linkText("Reset password")).click();

        Assert.assertEquals("Reset Password", webDriver.findElement(By.tagName("h1")).getText());

        int receivedEmailSize = simpleSmtpServer.getReceivedEmailSize();

        webDriver.findElement(By.name("email")).sendKeys("nonexistent@example.com");
        webDriver.findElement(By.xpath("//input[@value='Send reset password link']")).click();

        Assert.assertEquals("Instructions Sent", webDriver.findElement(By.tagName("h1")).getText());

        assertEquals(receivedEmailSize, simpleSmtpServer.getReceivedEmailSize());
    }

    public void takeScreenShot() throws IOException {
        File scrFile = ((TakesScreenshot)webDriver).getScreenshotAs(OutputType.FILE);
        File destFile = new File("testscreenshot-" + System.currentTimeMillis() + ".png");
        FileUtils.copyFile(scrFile, destFile);
        System.out.println("Screenshot in : " + destFile.getAbsolutePath());
    }
}
