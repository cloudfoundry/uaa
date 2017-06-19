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

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.account.UserAccountStatus;
import org.junit.After;
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
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.RestTemplate;

import java.security.SecureRandom;
import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class ForcedPasswordChangeIT {

    @Autowired @Rule
    public IntegrationTestRule integrationTestRule;

    @Autowired
    WebDriver webDriver;

    @Autowired
    TestClient testClient;

    @Autowired
    RestTemplate restTemplate;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private String userId;

    private  String userEmail;

    private String adminAccessToken;

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
        restTemplate = (RestTemplate)serverRunning.createRestTemplate();
        int randomInt = new SecureRandom().nextInt();
        adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin scim.write scim.read");
        userEmail = "user" + randomInt + "@example.com";
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+adminAccessToken);
        testClient.createUser(adminAccessToken, userEmail, userEmail, "secr3T", true);
        ResponseEntity<Map> response = restTemplate.exchange(baseUrl + "/Users?filter=userName eq '{user-name}'", HttpMethod.GET,
                new HttpEntity<>(headers), Map.class, userEmail);
        Map results = response.getBody();
        assertTrue("There should be more than zero users", (Integer) results.get("totalResults") > 0);
        Map firstUser = (Map) ((List) results.get("resources")).get(0);
        userId = (String)firstUser.get("id");
    }

    @After
    public void tearDown() throws Exception {
        webDriver.get(baseUrl + "/logout.do");
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+adminAccessToken);
        restTemplate.exchange(baseUrl + "/Users/{user-id}", HttpMethod.DELETE,
            new HttpEntity<>(headers), Object.class, userId);
    }

    @Test
    public void testHandleForceChangingPassword() throws Exception {
        navigateToForcePasswordChange();
        webDriver.findElement(By.name("password")).sendKeys("newsecr3T");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("newsecr3T");
        webDriver.findElement(By.xpath("//input[@value='Create new password']")).click();
        assertEquals(baseUrl+"/", webDriver.getCurrentUrl());
    }

    @Test
    public void testHandleForceChangingPasswordWithNewPasswordSameAsOld() throws Exception {
        navigateToForcePasswordChange();
        webDriver.findElement(By.name("password")).sendKeys("secr3T");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("secr3T");
        webDriver.findElement(By.xpath("//input[@value='Create new password']")).click();
        assertEquals(baseUrl+"/force_password_change", webDriver.getCurrentUrl());
        assertThat(webDriver.findElement(By.cssSelector(".error-message")).getText(),
            containsString("Your new password cannot be the same as the old password."));
    }

    @Test
    public void testHandleForcePasswordChangeInvalidConfirmation() throws Exception {
        navigateToForcePasswordChange();
        webDriver.findElement(By.name("password")).sendKeys("newsecr3T");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("invalid");
        webDriver.findElement(By.xpath("//input[@value='Create new password']")).click();
        assertEquals(baseUrl+"/force_password_change", webDriver.getCurrentUrl());
        assertThat(webDriver.findElement(By.cssSelector(".error-message")).getText(),
            containsString("Passwords must match and not be empty."));
    }

    @Test
    public void testHandleForcePasswordChangeEmptyConfirmation() throws Exception {
        navigateToForcePasswordChange();
        webDriver.findElement(By.name("password")).sendKeys("newsecr3T");
        webDriver.findElement(By.xpath("//input[@value='Create new password']")).click();
        assertEquals(baseUrl+"/force_password_change", webDriver.getCurrentUrl());
        assertThat(webDriver.findElement(By.cssSelector(".error-message")).getText(),
            containsString("Passwords must match and not be empty."));
    }

    @Test
    public void testRedirectForHandleForcePasswordChange() throws Exception {
        updateUserToForcePasswordChange();
        webDriver.get(baseUrl+"/profile");
        assertEquals(baseUrl+"/login", webDriver.getCurrentUrl());
        webDriver.findElement(By.name("username")).sendKeys(userEmail);
        webDriver.findElement(By.name("password")).sendKeys("secr3T");
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
        webDriver.findElement(By.name("password")).sendKeys("newsecr3T");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("newsecr3T");
        webDriver.findElement(By.xpath("//input[@value='Create new password']")).click();
        assertEquals(baseUrl+"/profile", webDriver.getCurrentUrl());
    }

    @Test
    public void testForcePasswordChangeThatFailsPasswordPolicy() {
        navigateToForcePasswordChange();
        String invalidNewPassword = new RandomValueStringGenerator(256).generate();
        webDriver.findElement(By.name("password")).sendKeys(invalidNewPassword);
        webDriver.findElement(By.name("password_confirmation")).sendKeys(invalidNewPassword);
        webDriver.findElement(By.xpath("//input[@value='Create new password']")).click();
        assertEquals(baseUrl+"/force_password_change", webDriver.getCurrentUrl());
        assertThat(webDriver.findElement(By.cssSelector(".error-message")).getText(),
            containsString("Password must be no more than 255 characters in length."));
    }

    private void navigateToForcePasswordChange() {
        updateUserToForcePasswordChange();
        webDriver.get(baseUrl+"/login");
        webDriver.findElement(By.name("username")).sendKeys(userEmail);
        webDriver.findElement(By.name("password")).sendKeys("secr3T");
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(),
            containsString("Force Change Password"));
        assertEquals(baseUrl+"/force_password_change", webDriver.getCurrentUrl());
    }

    private void updateUserToForcePasswordChange() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+adminAccessToken);
        UserAccountStatus userAccountStatus = new UserAccountStatus();
        userAccountStatus.setPasswordChangeRequired(true);
        ResponseEntity<UserAccountStatus> response = restTemplate.exchange(baseUrl + "/Users/{user-id}/status", HttpMethod.PATCH, new HttpEntity<UserAccountStatus>(userAccountStatus, headers), UserAccountStatus.class, userId);
        response.toString();
    }
}
