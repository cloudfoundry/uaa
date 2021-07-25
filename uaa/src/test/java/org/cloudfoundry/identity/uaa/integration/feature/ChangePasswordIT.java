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
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.RestTemplate;

import java.security.SecureRandom;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class ChangePasswordIT {

    public static final String PASSWORD = "s3Cret";
    public static final String NEW_PASSWORD = "newsecr3T";
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
    public void setUp() {
        int randomInt = new SecureRandom().nextInt();

        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");

        String scimClientId = "scim" + randomInt;
        testClient.createScimClient(adminAccessToken, scimClientId);

        String scimAccessToken = testClient.getOAuthAccessToken(scimClientId, "scimsecret", "client_credentials", "scim.read scim.write password.write");

        userEmail = "user" + randomInt + "@example.com";
        testClient.createUser(scimAccessToken, userEmail, userEmail, PASSWORD, true);
    }

    @Test
    public void testChangePassword() {
        webDriver.get(baseUrl + "/change_password");
        signIn(userEmail, PASSWORD);

        changePassword(PASSWORD, NEW_PASSWORD, "new");
        WebElement errorMessage = webDriver.findElement(By.className("error-message"));
        assertTrue(errorMessage.isDisplayed());
        assertEquals("Passwords must match and not be empty.", errorMessage.getText());

        changePassword(PASSWORD, NEW_PASSWORD, NEW_PASSWORD);
        signOut();

        signIn(userEmail, NEW_PASSWORD);
    }

    @Test
    public void displaysErrorWhenPasswordContravenesPolicy() {
        //the only policy we can contravene by default is the length

        String newPassword = new RandomValueStringGenerator(260).generate();
        webDriver.get(baseUrl + "/change_password");
        signIn(userEmail, PASSWORD);

        changePassword(PASSWORD, newPassword, newPassword);
        WebElement errorMessage = webDriver.findElement(By.className("error-message"));
        assertTrue(errorMessage.isDisplayed());
        assertEquals("Password must be no more than 255 characters in length.", errorMessage.getText());
    }

    private void changePassword(String originalPassword, String newPassword, String confirmPassword) {
        webDriver.findElement(By.xpath("//*[text()='"+userEmail+"']")).click();
        webDriver.findElement(By.linkText("Account Settings")).click();
        webDriver.findElement(By.linkText("Change Password")).click();
        webDriver.findElement(By.name("current_password")).sendKeys(originalPassword);
        webDriver.findElement(By.name("new_password")).sendKeys(newPassword);
        webDriver.findElement(By.name("confirm_password")).sendKeys(confirmPassword);

        webDriver.findElement(By.xpath("//input[@value='Change password']")).click();
    }

    private void signOut() {
        webDriver.findElement(By.xpath("//*[text()='"+userEmail+"']")).click();
        webDriver.findElement(By.linkText("Sign Out")).click();
    }

    private void signIn(String userName, String password) {
        webDriver.findElement(By.name("username")).sendKeys(userName);
        webDriver.findElement(By.name("password")).sendKeys(password);
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
    }
}
