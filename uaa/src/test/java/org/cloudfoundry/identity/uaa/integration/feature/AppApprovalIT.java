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
import org.cloudfoundry.identity.uaa.oauth.client.test.OAuth2ContextConfiguration;
import org.cloudfoundry.identity.uaa.oauth.client.test.OAuth2ContextExtension;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestAccountExtension;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.test.UaaWebDriver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.By;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.web.client.RestOperations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.createUnapprovedUser;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
@OAuth2ContextConfiguration(OAuth2ContextConfiguration.ClientCredentials.class)
class AppApprovalIT {

    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    private static final UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @RegisterExtension
    private static final TestAccountExtension testAccountExtension = TestAccountExtension.standard(serverRunning, testAccounts);

    @RegisterExtension
    private static final OAuth2ContextExtension context = OAuth2ContextExtension.withTestAccounts(serverRunning, testAccountExtension);

    public RestOperations restTemplate;

    @Autowired
    @RegisterExtension
    private IntegrationTestExtension integrationTestExtension;

    @Autowired
    UaaWebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @BeforeEach
    @AfterEach
    void logout_and_clear_cookies() {
        restTemplate = serverRunning.getRestTemplate();

        try {
            webDriver.get(baseUrl + "/logout.do");
        } catch (org.openqa.selenium.TimeoutException x) {
            //try again - this should not be happening - 20 second timeouts
            webDriver.get(baseUrl + "/logout.do");
        }
        webDriver.manage().deleteAllCookies();
    }

    @Test
    void approvingAnApp() {
        ResponseEntity<SearchResults<ScimGroup>> getGroups = restTemplate.exchange(baseUrl + "/Groups?filter=displayName eq '{displayName}'",
                HttpMethod.GET,
                null,
                new ParameterizedTypeReference<SearchResults<ScimGroup>>() {
                },
                "cloud_controller.read");
        ScimGroup group = getGroups.getBody().getResources().stream().findFirst().get();

        group.setDescription("Read about your clouds.");
        HttpHeaders headers = new HttpHeaders();
        headers.add("If-Match", Integer.toString(group.getVersion()));
        HttpEntity request = new HttpEntity(group, headers);
        restTemplate.exchange(baseUrl + "/Groups/{group-id}", HttpMethod.PUT, request, Object.class, group.getId());

        ScimUser user = createUnapprovedUser(serverRunning);

        // Visit app
        //simulate app redirect
        webDriver.get(baseUrl + "/oauth/authorize?client_id=app&redirect_uri=http://localhost:8080/app/&response_type=code&state=OcUiHB");
        // Sign in to login server
        webDriver.findElement(By.name("username")).sendKeys(user.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(user.getPassword());
        webDriver.clickAndWait(By.xpath("//input[@value='Sign in']"));

        // Authorize the app for some scopes
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).isEqualTo("Application Authorization");

        webDriver.findElement(By.xpath("//label[text()='Change your password']/preceding-sibling::input")).click();
        webDriver.findElement(By.xpath("//label[text()='Read user IDs and retrieve users by ID']/preceding-sibling::input")).click();
        webDriver.findElement(By.xpath("//label[text()='Read about your clouds.']/preceding-sibling::input"));

        webDriver.clickAndWait(By.xpath("//button[text()='Authorize']"));

        //validate that we were redirected to the app
        assertThat(webDriver.getCurrentUrl()).startsWith("http://localhost:8080/app/?code=");

        // View profile on the login server
        webDriver.get(baseUrl + "/profile");

        assertThat(webDriver.findElement(By.xpath("//input[@value='app-password.write']")).isSelected()).isFalse();
        assertThat(webDriver.findElement(By.xpath("//input[@value='app-scim.userids']")).isSelected()).isFalse();
        assertThat(webDriver.findElement(By.xpath("//input[@value='app-cloud_controller.read']")).isSelected()).isTrue();
        assertThat(webDriver.findElement(By.xpath("//input[@value='app-cloud_controller.write']")).isSelected()).isTrue();

        // Add approvals
        webDriver.findElement(By.xpath("//input[@value='app-password.write']")).click();
        webDriver.findElement(By.xpath("//input[@value='app-scim.userids']")).click();

        webDriver.clickAndWait(By.xpath("//button[text()='Update']"));

        assertThat(webDriver.findElement(By.xpath("//input[@value='app-password.write']")).isSelected()).isTrue();
        assertThat(webDriver.findElement(By.xpath("//input[@value='app-scim.userids']")).isSelected()).isTrue();
        assertThat(webDriver.findElement(By.xpath("//input[@value='app-cloud_controller.read']")).isSelected()).isTrue();
        assertThat(webDriver.findElement(By.xpath("//input[@value='app-cloud_controller.write']")).isSelected()).isTrue();

        // Revoke app
        webDriver.findElement(By.linkText("Revoke Access")).click();

        assertThat(webDriver.findElement(By.cssSelector(".revocation-modal p")).getText()).isEqualTo("Are you sure you want to revoke access to The Ultimate Oauth App?");

        // click cancel
        webDriver.findElement(By.cssSelector("#app-form .revocation-cancel")).click();

        webDriver.findElement(By.linkText("Revoke Access")).click();

        // click confirm
        webDriver.clickAndWait(By.cssSelector("#app-form .revocation-confirm"));

        assertThat(webDriver.findElements(By.xpath("//input[@value='app-password.write']"))).isEmpty();
    }

    @Test
    void scopeDescriptions() {
        ResponseEntity<SearchResults<ScimGroup>> getGroups = restTemplate.exchange(baseUrl + "/Groups?filter=displayName eq '{displayName}'",
                HttpMethod.GET,
                null,
                new ParameterizedTypeReference<SearchResults<ScimGroup>>() {
                },
                "cloud_controller.read");
        ScimGroup group = getGroups.getBody().getResources().stream().findFirst().get();

        group.setDescription("Read about <b>your</b> clouds.");
        HttpHeaders headers = new HttpHeaders();
        headers.add("If-Match", Integer.toString(group.getVersion()));
        HttpEntity request = new HttpEntity(group, headers);
        restTemplate.exchange(baseUrl + "/Groups/{group-id}", HttpMethod.PUT, request, Object.class, group.getId());

        ScimUser user = createUnapprovedUser(serverRunning);

        // Visit app
        //simulate app redirect
        webDriver.get(baseUrl + "/oauth/authorize?client_id=app&redirect_uri=http://localhost:8080/app/&response_type=code&state=OcUiHB");

        // Sign in to login server
        webDriver.findElement(By.name("username")).sendKeys(user.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(user.getPassword());
        webDriver.clickAndWait(By.xpath("//input[@value='Sign in']"));

        // Authorize the app for some scopes
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).isEqualTo("Application Authorization");

        webDriver.findElement(By.xpath("//label[text()='Read about <b>your</b> clouds.']/preceding-sibling::input"));
    }

    @Test
    void invalidAppRedirectDisplaysError() {
        ScimUser user = createUnapprovedUser(serverRunning);

        // given we vist the app (specifying an invalid redirect - incorrect protocol https)
        //simulate app redirect
        webDriver.get(baseUrl + "/oauth/authorize?client_id=app&redirect_uri=https://localhost:8080/app/&response_type=code&state=a4QXYw");
        // Sign in to login server
        webDriver.findElement(By.name("username")).sendKeys(user.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(user.getPassword());
        webDriver.clickAndWait(By.xpath("//input[@value='Sign in']"));

        // Authorize the app for some scopes
        assertThat(webDriver.findElement(By.className("alert-error")).getText())
                .matches("^Invalid redirect (.*) did not match one of the registered values");
    }
}
