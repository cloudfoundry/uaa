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

import com.icegreen.greenmail.util.GreenMail;
import com.icegreen.greenmail.util.GreenMailUtil;
import jakarta.mail.internet.MimeMessage;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.login.test.UnlessProfileActive;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.test.UaaWebDriver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.By;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.web.client.RestTemplate;

import java.security.SecureRandom;
import java.util.Collections;

import static org.apache.commons.lang3.StringUtils.contains;
import static org.assertj.core.api.Assertions.assertThat;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
@UnlessProfileActive(values = "saml")
class ResetPasswordIT {

    @Autowired
    @RegisterExtension
    private IntegrationTestExtension integrationTestExtension;

    @Autowired
    UaaWebDriver webDriver;

    @Autowired
    GreenMail greenMail;

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

    @BeforeEach
    @AfterEach
    void logoutAndClearCookies() {
        try {
            webDriver.get(baseUrl + "/logout.do");
        } catch (org.openqa.selenium.TimeoutException x) {
            webDriver.get(baseUrl + "/logout.do");
        }
        webDriver.manage().deleteAllCookies();
    }

    @BeforeEach
    void setUp() {
        SecureRandom secureRandom = new SecureRandom();

        scimClientId = "scim" + secureRandom.nextInt();
        authCodeClientId = "auth_code_" + secureRandom.nextInt();
        username = "user" + secureRandom.nextInt();
        email = username + "@example.com";

        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");
        testClient.createScimClient(adminAccessToken, scimClientId);
        UaaClientDetails authCodeClient = new UaaClientDetails(authCodeClientId, "oauth", "uaa.user", "authorization_code,refresh_token", null, "http://testzonedoesnotexist.localhost");
        authCodeClient.setClientSecret("scimsecret");
        authCodeClient.setAutoApproveScopes(Collections.singletonList("uaa.user"));
        IntegrationTestUtils.createClient(adminAccessToken, baseUrl, authCodeClient);
        String scimAccessToken = testClient.getOAuthAccessToken(scimClientId, "scimsecret", "client_credentials", "scim.read scim.write password.write");
        testClient.createUser(scimAccessToken, username, email, "secr3T", true);
    }

    @AfterEach
    void tearDown() {
        webDriver.get(baseUrl + "/logout.do");
    }

    @Test
    void resettingAPasswordWithUsername() {
        beginPasswordReset(username);
        finishPasswordReset(username, email);
    }

    @Test
    void resettingAPasswordWithPrimaryEmail() {
        int receivedEmailSize = greenMail.getReceivedMessages().length;
        beginPasswordReset(email);
        assertThat(greenMail.getReceivedMessages()).hasSize(receivedEmailSize);
    }

    @Test
    void resetPassword_with_clientRedirect() throws Exception {
        webDriver.get(baseUrl + "/forgot_password?client_id=" + scimClientId + "&redirect_uri=http://testzonedoesnotexist.localhost");
        assertThat(webDriver.findElement(By.tagName("h1")).getText()).isEqualTo("Reset Password");

        int receivedEmailSize = greenMail.getReceivedMessages().length;

        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.clickAndWait(By.xpath("//input[@value='Send reset password link']"));
        assertThat(webDriver.findElement(By.tagName("h1")).getText()).isEqualTo("Instructions Sent");

        greenMail.waitForIncomingEmail(5000, receivedEmailSize + 1);
        assertThat(greenMail.getReceivedMessages()).hasSize(receivedEmailSize + 1);
        MimeMessage message = greenMail.getReceivedMessages()[receivedEmailSize];
        assertThat(message.getHeader("To")[0]).isEqualTo(email);
        assertThat(GreenMailUtil.getBody(message)).contains("Reset your password");

        assertThat(webDriver.findElement(By.cssSelector(".instructions-sent")).getText()).isEqualTo("Please check your email for a reset password link.");

        String link = testClient.extractLink(GreenMailUtil.getBody(message));
        assertThat(contains(link, "@")).isFalse();
        assertThat(contains(link, "%40")).isFalse();
        webDriver.get(link);

        webDriver.findElement(By.name("password")).sendKeys("new_password");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("new_password");
        webDriver.clickAndWait(By.xpath("//input[@value='Create new password']"));

        assertThat(webDriver.getCurrentUrl()).isEqualTo(baseUrl + "/login?success=password_reset&form_redirect_uri=http://testzonedoesnotexist.localhost");
    }

    @Test
    void notAutoLoginAfterResetPassword() throws Exception {
        webDriver.get(baseUrl + "/oauth/authorize?client_id=" + authCodeClientId + "&redirect_uri=http://testzonedoesnotexist.localhost&grant_type=authorization_code&response_type=code");
        webDriver.clickAndWait(By.linkText("Reset password"));
        assertThat(webDriver.findElement(By.tagName("h1")).getText()).isEqualTo("Reset Password");

        int receivedEmailSize = greenMail.getReceivedMessages().length;

        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.clickAndWait(By.xpath("//input[@value='Send reset password link']"));
        assertThat(webDriver.findElement(By.tagName("h1")).getText()).isEqualTo("Instructions Sent");

        greenMail.waitForIncomingEmail(5000, receivedEmailSize + 1);
        assertThat(greenMail.getReceivedMessages()).hasSize(receivedEmailSize + 1);
        MimeMessage message = greenMail.getReceivedMessages()[receivedEmailSize];
        assertThat(message.getHeader("To")[0]).isEqualTo(email);
        assertThat(GreenMailUtil.getBody(message)).contains("Reset your password");

        assertThat(webDriver.findElement(By.cssSelector(".instructions-sent")).getText()).isEqualTo("Please check your email for a reset password link.");

        String link = testClient.extractLink(GreenMailUtil.getBody(message));
        assertThat(link).doesNotContain("@")
                .doesNotContain("%40");
        webDriver.get(link);

        webDriver.findElement(By.name("password")).sendKeys("new_password");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("new_password");
        webDriver.clickAndWait(By.xpath("//input[@value='Create new password']"));

        assertThat(webDriver.getCurrentUrl()).isEqualTo(baseUrl + "/login?success=password_reset");
        assertThat(webDriver.findElement(By.cssSelector(".alert-success")).getText()).contains("Password reset successful");
        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.findElement(By.name("password")).sendKeys("new_password");
        webDriver.clickAndWait(By.xpath("//input[@value='Sign in']"));

        assertThat(webDriver.getCurrentUrl()).matches("^http://testzonedoesnotexist\\.localhost.*\\?code=.*");
    }

    @Test
    void resettingAPasswordForANonExistentUser() {
        int receivedEmailSize = greenMail.getReceivedMessages().length;
        beginPasswordReset("nonexistent_user");
        assertThat(greenMail.getReceivedMessages()).hasSize(receivedEmailSize);
    }

    @Test
    void resettingAPasswordWithInvalidPassword() {
        beginPasswordReset(username);
        String link = getPasswordResetLink(email);
        webDriver.get(link);

        webDriver.findElement(By.name("password")).sendKeys("newsecret");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("");
        webDriver.clickAndWait(By.xpath("//input[@value='Create new password']"));
        assertThat(webDriver.findElement(By.cssSelector(".error-message")).getText()).contains("Passwords must match and not be empty.");
    }

    @Test
    void codesCanOnlyBeUsedOnce() {
        beginPasswordReset(username);
        String link = getPasswordResetLink(email);
        webDriver.get(link);
        webDriver.get(link);
        assertThat(webDriver.findElement(By.cssSelector(".error-message")).getText()).contains("Sorry, your reset password link is no longer valid. You can request another one below.");
    }

    @Test
    void resetPassword_displaysErrorMessage_WhenPasswordIsInvalid() {
        String newPassword = new RandomValueStringGenerator(260).generate();
        beginPasswordReset(username);

        String link = getPasswordResetLink(email);
        webDriver.get(link);

        webDriver.findElement(By.name("password")).sendKeys(newPassword);
        webDriver.findElement(By.name("password_confirmation")).sendKeys(newPassword);
        webDriver.clickAndWait(By.xpath("//input[@value='Create new password']"));
        assertThat(webDriver.findElement(By.cssSelector(".error-message")).getText()).contains("Password must be no more than 255 characters in length.");
    }

    @Test
    void resetPassword_displaysErrorMessage_NewPasswordSameAsOld() {
        beginPasswordReset(username);
        String link = getPasswordResetLink(email);
        webDriver.get(link);

        webDriver.findElement(By.name("password")).sendKeys("secr3T");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("secr3T");
        webDriver.clickAndWait(By.xpath("//input[@value='Create new password']"));
        assertThat(webDriver.findElement(By.cssSelector(".error-message")).getText()).contains("Your new password cannot be the same as the old password.");
    }

    private void beginPasswordReset(String username) {
        webDriver.get(baseUrl + "/login");
        assertThat(webDriver.getTitle()).isEqualTo("Cloud Foundry");
        webDriver.clickAndWait(By.linkText("Reset password"));
        assertThat(webDriver.findElement(By.tagName("h1")).getText()).isEqualTo("Reset Password");

        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.clickAndWait(By.xpath("//input[@value='Send reset password link']"));
        assertThat(webDriver.findElement(By.tagName("h1")).getText()).isEqualTo("Instructions Sent");
    }

    private String getPasswordResetLink(String email) {
        greenMail.waitForIncomingEmail(5000, 1);
        MimeMessage[] messages = greenMail.getReceivedMessages();
        MimeMessage message = messages[messages.length - 1];
        try {
            assertThat(message.getHeader("To")[0]).isEqualTo(email);
            String body = GreenMailUtil.getBody(message);
            assertThat(body).contains("Reset your password");

            assertThat(webDriver.findElement(By.cssSelector(".instructions-sent")).getText()).isEqualTo("Please check your email for a reset password link.");

            return testClient.extractLink(body);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void finishPasswordReset(String username, String email) {
        String link = getPasswordResetLink(email);
        webDriver.get(link);

        webDriver.findElement(By.name("password")).sendKeys("newsecr3T");
        webDriver.findElement(By.name("password_confirmation")).sendKeys("newsecr3T");
        webDriver.clickAndWait(By.xpath("//input[@value='Create new password']"));
        assertThat(webDriver.getCurrentUrl()).isEqualTo(baseUrl + "/login?success=password_reset");

        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.findElement(By.name("password")).sendKeys("newsecr3T");
        webDriver.clickAndWait(By.xpath("//input[@value='Sign in']"));

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Where to?");
    }
}
