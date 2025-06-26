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
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.client.test.TestAccounts;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.test.UaaWebDriver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.By;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.net.URI;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Iterator;

import static org.assertj.core.api.Assertions.assertThat;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
class CreateAccountIT {

    public static final String SECRET = "s3Cret";

    @Autowired
    TestAccounts testAccounts;

    @Autowired
    @RegisterExtension
    private IntegrationTestExtension integrationTestExtension;

    @Autowired
    UaaWebDriver webDriver;

    @Autowired
    SimpleSmtpServer simpleSmtpServer;

    @Autowired
    TestClient testClient;

    @Value("${integration.test.base_url}")
    String baseUrl;

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

    @Test
    void userInitiatedSignup() {
        int receivedEmailSize = simpleSmtpServer.getReceivedEmailSize();
        String userEmail = startCreateUserFlow(SECRET);

        assertThat(simpleSmtpServer.getReceivedEmailSize()).isEqualTo(receivedEmailSize + 1);
        Iterator<SmtpMessage> receivedEmail = simpleSmtpServer.getReceivedEmail();
        SmtpMessage message = receivedEmail.next();
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
        webDriver.clickAndWait(By.xpath("//input[@value='Sign in']"));

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Where to?");
    }

    @Test
    void clientInitiatedSignup() {
        String userEmail = "user" + new SecureRandom().nextInt() + "@example.com";
        webDriver.get(baseUrl + "/create_account?client_id=app");

        assertThat(webDriver.findElement(By.tagName("h1")).getText()).isEqualTo("Create your account");

        int receivedEmailSize = simpleSmtpServer.getReceivedEmailSize();

        webDriver.findElement(By.name("email")).sendKeys(userEmail);
        webDriver.findElement(By.name("password")).sendKeys(SECRET);
        webDriver.findElement(By.name("password_confirmation")).sendKeys(SECRET);
        webDriver.clickAndWait(By.xpath("//input[@value='Send activation link']"));

        assertThat(simpleSmtpServer.getReceivedEmailSize()).isEqualTo(receivedEmailSize + 1);
        Iterator<SmtpMessage> receivedEmail = simpleSmtpServer.getReceivedEmail();
        SmtpMessage message = receivedEmail.next();
        receivedEmail.remove();
        assertThat(message.getHeaderValue("To")).isEqualTo(userEmail);
        assertThat(message.getBody()).contains("Activate your account");

        assertThat(webDriver.findElement(By.cssSelector(".instructions-sent")).getText()).isEqualTo("Please check email for an activation link.");

        String link = testClient.extractLink(message.getBody());
        assertThat(link).isNotEmpty();

        webDriver.get(link);
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).doesNotContain("Where to?");

        webDriver.findElement(By.name("username")).sendKeys(userEmail);
        webDriver.findElement(By.name("password")).sendKeys(SECRET);
        webDriver.clickAndWait(By.xpath("//input[@value='Sign in']"));

        // Authorize the app for some scopes
        webDriver.get(baseUrl + "/oauth/authorize?client_id=app&redirect_uri=http://localhost:8080/app/&response_type=code&state=3e5u7U");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).isEqualTo("Application Authorization");
        webDriver.clickAndWait(By.xpath("//button[text()='Authorize']"));
        assertThat(webDriver.getCurrentUrl()).startsWith("http://localhost:8080/app/?code=");
    }

    @Test
    void enteringContraveningPasswordShowsErrorMessage() {
        startCreateUserFlow(new RandomValueStringGenerator(260).generate());
        assertThat(webDriver.findElement(By.cssSelector(".alert-error")).getText()).isEqualTo("Password must be no more than 255 characters in length.");
    }

    private String startCreateUserFlow(String secret) {
        String userEmail = "user" + new SecureRandom().nextInt() + "@example.com";

        webDriver.get(baseUrl + "/");
        webDriver.clickAndWait(By.xpath("//*[text()='Create account']"));

        assertThat(webDriver.findElement(By.tagName("h1")).getText()).isEqualTo("Create your account");

        webDriver.findElement(By.name("email")).sendKeys(userEmail);
        webDriver.findElement(By.name("password")).sendKeys(secret);
        webDriver.findElement(By.name("password_confirmation")).sendKeys(secret);

        webDriver.clickAndWait(By.xpath("//input[@value='Send activation link']"));
        return userEmail;
    }

    @Test
    void emailDomainRegisteredWithIDPDoesNotAllowAccountCreation() throws Exception {
        String adminToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");
        IdentityProvider<OIDCIdentityProviderDefinition> oidcProvider = new IdentityProvider<OIDCIdentityProviderDefinition>().setName("oidc_provider").setActive(true).setType(OriginKeys.OIDC10).setOriginKey(OriginKeys.OIDC10).setConfig(new OIDCIdentityProviderDefinition());
        oidcProvider.getConfig().setAuthUrl(URI.create("http://example.com").toURL());
        oidcProvider.getConfig().setShowLinkText(false);
        oidcProvider.getConfig().setTokenUrl(URI.create("http://localhost:8080/uaa/idp_login").toURL());
        oidcProvider.getConfig().setTokenKeyUrl(URI.create("http://localhost:8080/uaa/idp_login").toURL());
        oidcProvider.getConfig().setEmailDomain(Collections.singletonList("example.com"));
        oidcProvider.getConfig().setRelyingPartyId("client_id");
        oidcProvider.getConfig().setRelyingPartySecret("client_secret");
        IntegrationTestUtils.createOrUpdateProvider(adminToken, baseUrl, oidcProvider);

        try {
            startCreateUserFlow("test");
            assertThat(webDriver.findElement(By.cssSelector(".alert-error")).getText()).isEqualTo("Account sign-up is not required for this email domain. Please login with the identity provider");
            webDriver.clickAndWait(By.xpath("//input[@value='Login with provider']"));
            assertThat(webDriver.getCurrentUrl()).matches("^https?://example.com/.*");
        } finally {
            IntegrationTestUtils.deleteProvider(adminToken, baseUrl, OriginKeys.UAA, OriginKeys.OIDC10);
        }
    }
}
