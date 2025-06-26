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

import org.cloudfoundry.identity.uaa.ServerRunningExtension;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.test.UaaWebDriver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.By;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.web.client.RestTemplate;

import java.security.SecureRandom;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.updateUserToForcePasswordChange;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
class ForcedPasswordChangeIT {

    @Autowired
    @RegisterExtension
    private IntegrationTestExtension integrationTestExtension;

    @Autowired
    UaaWebDriver webDriver;

    @Autowired
    TestClient testClient;

    @Autowired
    RestTemplate restTemplate;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    private String userId;

    private String userEmail;

    private String adminAccessToken;

    @BeforeEach
    @AfterEach
    void logoutAndClearCookies() {
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
        restTemplate = serverRunning.createRestTemplate();
        int randomInt = new SecureRandom().nextInt();
        adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin scim.write scim.read");
        userEmail = "user" + randomInt + "@example.com";
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + adminAccessToken);
        testClient.createUser(adminAccessToken, userEmail, userEmail, "secr3T", true);
        ResponseEntity<Map> response = restTemplate.exchange(baseUrl + "/Users?filter=userName eq  \"{user-name}\"", HttpMethod.GET,
                new HttpEntity<>(headers), Map.class, userEmail);
        Map results = response.getBody();
        assertThat((Integer) results.get("totalResults")).as("There should be more than zero users").isPositive();
        Map firstUser = (Map) ((List) results.get("resources")).getFirst();
        userId = (String) firstUser.get("id");
    }

    @AfterEach
    void tearDown() {
        webDriver.get(baseUrl + "/logout.do");
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + adminAccessToken);
        restTemplate.exchange(baseUrl + "/Users/{user-id}", HttpMethod.DELETE,
                new HttpEntity<>(headers), Object.class, userId);
    }

    @Test
    void handleForcePasswordChange() {
        navigateToForcePasswordChange();
        webDriver.findElement(By.name("password")).sendKeys("newsecr3T");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("newsecr3T");

        var session1 = webDriver.manage().getCookieNamed("JSESSIONID");
        webDriver.clickAndWait(By.xpath("//input[@value='Create new password']"));
        var session2 = webDriver.manage().getCookieNamed("JSESSIONID");
        assertThat(session2).isEqualTo(session1);
        assertThat(session1).isNotNull();

        assertThat(webDriver.getCurrentUrl()).isEqualTo(baseUrl + "/");
    }

    @Test
    void handleForcePasswordChangeWithNewPasswordSameAsOld() {
        navigateToForcePasswordChange();
        webDriver.findElement(By.name("password")).sendKeys("secr3T");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("secr3T");
        webDriver.clickAndWait(By.xpath("//input[@value='Create new password']"));
        assertThat(webDriver.getCurrentUrl()).isEqualTo(baseUrl + "/force_password_change");
        assertThat(webDriver.findElement(By.cssSelector(".error-message")).getText()).contains("Your new password cannot be the same as the old password.");
    }

    @Test
    void handleForcePasswordChangeWithPasswordDoesNotMatchPasswordConfirmation() {
        navigateToForcePasswordChange();
        webDriver.findElement(By.name("password")).sendKeys("newsecr3T");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("invalid");
        webDriver.clickAndWait(By.xpath("//input[@value='Create new password']"));
        assertThat(webDriver.getCurrentUrl()).isEqualTo(baseUrl + "/force_password_change");
        assertThat(webDriver.findElement(By.cssSelector(".error-message")).getText()).contains("Passwords must match and not be empty.");
    }

    @Test
    void handleForcePasswordChangeWithEmptyPasswordConfirmation() {
        navigateToForcePasswordChange();
        webDriver.findElement(By.name("password")).sendKeys("newsecr3T");
        webDriver.clickAndWait(By.xpath("//input[@value='Create new password']"));
        assertThat(webDriver.getCurrentUrl()).isEqualTo(baseUrl + "/force_password_change");
        assertThat(webDriver.findElement(By.cssSelector(".error-message")).getText()).contains("Passwords must match and not be empty.");
    }

    @Test
    void handleForcePasswordChangeDoesRedirectToOriginalUrl() {
        updateUserToForcePasswordChange(restTemplate, baseUrl, adminAccessToken, userId);
        webDriver.get(baseUrl + "/profile");
        assertThat(webDriver.getCurrentUrl()).isEqualTo(baseUrl + "/login");
        webDriver.findElement(By.name("username")).sendKeys(userEmail);
        webDriver.findElement(By.name("password")).sendKeys("secr3T");
        webDriver.clickAndWait(By.xpath("//input[@value='Sign in']"));

        assertThat(webDriver.getCurrentUrl()).isEqualTo(baseUrl + "/force_password_change");
        webDriver.findElement(By.name("password")).sendKeys("newsecr3T");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("newsecr3T");

        var session1 = webDriver.manage().getCookieNamed("JSESSIONID");
        webDriver.clickAndWait(By.xpath("//input[@value='Create new password']"));
        var session2 = webDriver.manage().getCookieNamed("JSESSIONID");
        assertThat(session2).isEqualTo(session1);
        assertThat(session1).isNotNull();
        assertThat(webDriver.getCurrentUrl()).isEqualTo(baseUrl + "/profile");
    }

    @Test
    void forcePasswordChangeThatFailsPasswordPolicy() {
        navigateToForcePasswordChange();
        String invalidNewPassword = new RandomValueStringGenerator(256).generate();
        webDriver.findElement(By.name("password")).sendKeys(invalidNewPassword);
        webDriver.findElement(By.name("password_confirmation")).sendKeys(invalidNewPassword);
        webDriver.clickAndWait(By.xpath("//input[@value='Create new password']"));
        assertThat(webDriver.getCurrentUrl()).isEqualTo(baseUrl + "/force_password_change");
        assertThat(webDriver.findElement(By.cssSelector(".error-message")).getText()).contains("Password must be no more than 255 characters in length.");
    }

    private void navigateToForcePasswordChange() {
        updateUserToForcePasswordChange(restTemplate, baseUrl, adminAccessToken, userId);
        webDriver.get(baseUrl + "/login");
        webDriver.findElement(By.name("username")).sendKeys(userEmail);
        webDriver.findElement(By.name("password")).sendKeys("secr3T");
        webDriver.clickAndWait(By.xpath("//input[@value='Sign in']"));
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Force Change Password");
        assertThat(webDriver.getCurrentUrl()).isEqualTo(baseUrl + "/force_password_change");
    }
}
