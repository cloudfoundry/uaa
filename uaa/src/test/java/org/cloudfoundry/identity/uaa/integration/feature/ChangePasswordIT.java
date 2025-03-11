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
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.test.UaaWebDriver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.web.client.RestTemplate;

import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
public class ChangePasswordIT {

    public static final String PASSWORD = "s3Cret";
    public static final String NEW_PASSWORD = "newsecr3T";

    @Autowired
    @RegisterExtension
    private IntegrationTestExtension integrationTestExtension;

    @Autowired
    UaaWebDriver webDriver;

    @Autowired
    SimpleSmtpServer simpleSmtpServer;

    @Autowired
    TestClient testClient;

    @Autowired
    RestTemplate restTemplate;

    @Value("${integration.test.base_url}")
    String baseUrl;

    private String userEmail;

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

    @BeforeEach
    void setUp() {
        int randomInt = new SecureRandom().nextInt();

        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");

        String scimClientId = "scim" + randomInt;
        testClient.createScimClient(adminAccessToken, scimClientId);

        String scimAccessToken = testClient.getOAuthAccessToken(scimClientId, "scimsecret", "client_credentials", "scim.read scim.write password.write");

        userEmail = "user" + randomInt + "@example.com";
        testClient.createUser(scimAccessToken, userEmail, userEmail, PASSWORD, true);
    }

    @Test
    void testChangePassword() {
        webDriver.get(baseUrl + "/change_password");
        signIn(userEmail, PASSWORD);

        changePassword(PASSWORD, NEW_PASSWORD, "new");
        WebElement errorMessage = webDriver.findElement(By.className("error-message"));
        assertThat(errorMessage.isDisplayed()).isTrue();
        assertThat(errorMessage.getText()).isEqualTo("Passwords must match and not be empty.");

        changePassword(PASSWORD, NEW_PASSWORD, NEW_PASSWORD);
        signOut();

        signIn(userEmail, NEW_PASSWORD);
    }

    @Test
    void displaysErrorWhenPasswordContravenesPolicy() {
        //the only policy we can contravene by default is the length

        String newPassword = new RandomValueStringGenerator(260).generate();
        webDriver.get(baseUrl + "/change_password");
        signIn(userEmail, PASSWORD);

        changePassword(PASSWORD, newPassword, newPassword);
        WebElement errorMessage = webDriver.findElement(By.className("error-message"));
        assertThat(errorMessage.isDisplayed()).isTrue();
        assertThat(errorMessage.getText()).isEqualTo("Password must be no more than 255 characters in length.");
    }

    private void changePassword(String originalPassword, String newPassword, String confirmPassword) {
        webDriver.findElement(By.xpath("//*[text()='" + userEmail + "']")).click();
        webDriver.findElement(By.linkText("Account Settings")).click();
        webDriver.findElement(By.linkText("Change Password")).click();
        webDriver.findElement(By.name("current_password")).sendKeys(originalPassword);
        webDriver.findElement(By.name("new_password")).sendKeys(newPassword);
        webDriver.findElement(By.name("confirm_password")).sendKeys(confirmPassword);

        webDriver.clickAndWait(By.xpath("//input[@value='Change password']"));
    }

    private void signOut() {
        webDriver.findElement(By.xpath("//*[text()='" + userEmail + "']")).click();
        webDriver.clickAndWait(By.linkText("Sign Out"));
    }

    private void signIn(String userName, String password) {
        webDriver.findElement(By.name("username")).sendKeys(userName);
        webDriver.findElement(By.name("password")).sendKeys(password);
        webDriver.clickAndWait(By.xpath("//input[@value='Sign in']"));
    }
}
