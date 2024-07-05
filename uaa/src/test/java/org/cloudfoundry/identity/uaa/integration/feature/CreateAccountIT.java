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
import com.dumbster.smtp.SmtpMessage;
import org.assertj.core.api.Assertions;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.client.test.TestAccounts;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.junit.Rule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.net.URL;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Iterator;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
class CreateAccountIT {

    public static final String SECRET = "s3Cret";

    @Autowired
    TestAccounts testAccounts;

    @Autowired
    @Rule
    public IntegrationTestRule integrationTestRule;

    @Autowired
    WebDriver webDriver;

    @Autowired
    SimpleSmtpServer simpleSmtpServer;

    @Autowired
    TestClient testClient;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Value("${integration.test.app_url}")
    String appUrl;

    @BeforeEach
    @AfterEach
    void logout_and_clear_cookies() {
        try {
            webDriver.get(baseUrl + "/logout.do");
        } catch (org.openqa.selenium.TimeoutException x) {
            //try again - this should not be happening - 20 second timeouts
            webDriver.get(baseUrl + "/logout.do");
        }
        webDriver.get(appUrl + "/j_spring_security_logout");
        webDriver.manage().deleteAllCookies();
    }

    @Test
    void userInitiatedSignup() {
        int receivedEmailSize = simpleSmtpServer.getReceivedEmailSize();
        String userEmail = startCreateUserFlow(SECRET);

        assertThat(simpleSmtpServer.getReceivedEmailSize()).isEqualTo(receivedEmailSize + 1);
        Iterator receivedEmail = simpleSmtpServer.getReceivedEmail();
        SmtpMessage message = (SmtpMessage) receivedEmail.next();
        receivedEmail.remove();
        assertThat(message.getHeaderValue("To")).isEqualTo(userEmail);
        String body = message.getBody();
        assertThat(body).contains("Activate your account");

        assertThat(webDriver.findElement(By.tagName("h1")).getText()).isEqualTo("Create your account");
        assertThat(webDriver.findElement(By.cssSelector(".instructions-sent")).getText()).isEqualTo("Please check email for an activation link.");

        String link = testClient.extractLink(body);
        assertThat(link).isNotEmpty()
                .doesNotContain("@")
                .doesNotContain("%40");

        webDriver.get(link);
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).doesNotContain("Where to?");

        webDriver.findElement(By.name("username")).sendKeys(userEmail);
        webDriver.findElement(By.name("password")).sendKeys(SECRET);
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Where to?");
    }

    @Test
    void clientInitiatedSignup() {
        String userEmail = "user" + new SecureRandom().nextInt() + "@example.com";
        webDriver.get(baseUrl + "/create_account?client_id=app");

        Assertions.assertThat(webDriver.findElement(By.tagName("h1")).getText()).isEqualTo("Create your account");

        int receivedEmailSize = simpleSmtpServer.getReceivedEmailSize();

        webDriver.findElement(By.name("email")).sendKeys(userEmail);
        webDriver.findElement(By.name("password")).sendKeys(SECRET);
        webDriver.findElement(By.name("password_confirmation")).sendKeys(SECRET);
        webDriver.findElement(By.xpath("//input[@value='Send activation link']")).click();

        assertThat(simpleSmtpServer.getReceivedEmailSize()).isEqualTo(receivedEmailSize + 1);
        Iterator<SmtpMessage> receivedEmail = simpleSmtpServer.getReceivedEmail();
        SmtpMessage message = receivedEmail.next();
        receivedEmail.remove();
        assertThat(message.getHeaderValue("To")).isEqualTo(userEmail);
        assertThat(message.getBody()).contains("Activate your account");

        Assertions.assertThat(webDriver.findElement(By.cssSelector(".instructions-sent")).getText()).isEqualTo("Please check email for an activation link.");

        String link = testClient.extractLink(message.getBody());
        assertThat(link).isNotEmpty();

        webDriver.get(link);
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).doesNotContain("Where to?");

        webDriver.findElement(By.name("username")).sendKeys(userEmail);
        webDriver.findElement(By.name("password")).sendKeys(SECRET);
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        // Authorize the app for some scopes
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).isEqualTo("Application Authorization");
        webDriver.findElement(By.xpath("//button[text()='Authorize']")).click();
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).isEqualTo("Sample Home Page");
    }

    @Test
    void enteringContraveningPasswordShowsErrorMessage() {
        startCreateUserFlow(new RandomValueStringGenerator(260).generate());
        assertThat(webDriver.findElement(By.cssSelector(".alert-error")).getText()).isEqualTo("Password must be no more than 255 characters in length.");
    }

    private String startCreateUserFlow(String secret) {
        String userEmail = "user" + new SecureRandom().nextInt() + "@example.com";

        webDriver.get(baseUrl + "/");
        webDriver.findElement(By.xpath("//*[text()='Create account']")).click();

        assertThat(webDriver.findElement(By.tagName("h1")).getText()).isEqualTo("Create your account");

        webDriver.findElement(By.name("email")).sendKeys(userEmail);
        webDriver.findElement(By.name("password")).sendKeys(secret);
        webDriver.findElement(By.name("password_confirmation")).sendKeys(secret);

        webDriver.findElement(By.xpath("//input[@value='Send activation link']")).click();
        return userEmail;
    }

    @Test
    void emailDomainRegisteredWithIDPDoesNotAllowAccountCreation() throws Exception {
        String adminToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");
        IdentityProvider<OIDCIdentityProviderDefinition> oidcProvider = new IdentityProvider<OIDCIdentityProviderDefinition>().setName("oidc_provider").setActive(true).setType(OriginKeys.OIDC10).setOriginKey(OriginKeys.OIDC10).setConfig(new OIDCIdentityProviderDefinition());
        oidcProvider.getConfig().setAuthUrl(new URL("http://example.com"));
        oidcProvider.getConfig().setShowLinkText(false);
        oidcProvider.getConfig().setTokenUrl(new URL("http://localhost:8080/uaa/idp_login"));
        oidcProvider.getConfig().setTokenKeyUrl(new URL("http://localhost:8080/uaa/idp_login"));
        oidcProvider.getConfig().setEmailDomain(Collections.singletonList("example.com"));
        oidcProvider.getConfig().setRelyingPartyId("client_id");
        oidcProvider.getConfig().setRelyingPartySecret("client_secret");
        IntegrationTestUtils.createOrUpdateProvider(adminToken, baseUrl, oidcProvider);

        try {
            startCreateUserFlow("test");
            assertThat(webDriver.findElement(By.cssSelector(".alert-error")).getText()).isEqualTo("Account sign-up is not required for this email domain. Please login with the identity provider");
            webDriver.findElement(By.xpath("//input[@value='Login with provider']")).click();
            assertThat(webDriver.getCurrentUrl()).matches("^https?://example.com/.*");
        } finally {
            IntegrationTestUtils.deleteProvider(adminToken, baseUrl, OriginKeys.UAA, OriginKeys.OIDC10);
        }
    }
}
