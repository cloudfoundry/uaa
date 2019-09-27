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
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.RestOperations;

import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.createUnapprovedUser;
import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
@OAuth2ContextConfiguration(OAuth2ContextConfiguration.ClientCredentials.class)
public class AppApprovalIT {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public OAuth2ContextSetup context = OAuth2ContextSetup.withTestAccounts(serverRunning, testAccounts);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    public RestOperations restTemplate;


    @Autowired @Rule
    public IntegrationTestRule integrationTestRule;

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Value("${integration.test.app_url}")
    String appUrl;

    @Before
    @After
    public void logout_and_clear_cookies() {
        restTemplate = serverRunning.getRestTemplate();

        try {
            webDriver.get(baseUrl + "/logout.do");
        }catch (org.openqa.selenium.TimeoutException x) {
            //try again - this should not be happening - 20 second timeouts
            webDriver.get(baseUrl + "/logout.do");
        }
        webDriver.get(appUrl+"/j_spring_security_logout");
        webDriver.manage().deleteAllCookies();
    }

    @Test
    public void testApprovingAnApp() {
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
        webDriver.get(appUrl);

        // Sign in to login server
        webDriver.findElement(By.name("username")).sendKeys(user.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(user.getPassword());
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        // Authorize the app for some scopes
        Assert.assertEquals("Application Authorization", webDriver.findElement(By.cssSelector("h1")).getText());

        webDriver.findElement(By.xpath("//label[text()='Change your password']/preceding-sibling::input")).click();
        webDriver.findElement(By.xpath("//label[text()='Read user IDs and retrieve users by ID']/preceding-sibling::input")).click();
        webDriver.findElement(By.xpath("//label[text()='Read about your clouds.']/preceding-sibling::input"));

        webDriver.findElement(By.xpath("//button[text()='Authorize']")).click();

        Assert.assertEquals("Sample Home Page", webDriver.findElement(By.cssSelector("h1")).getText());

        // View profile on the login server
        webDriver.get(baseUrl + "/profile");

        Assert.assertFalse(webDriver.findElement(By.xpath("//input[@value='app-password.write']")).isSelected());
        Assert.assertFalse(webDriver.findElement(By.xpath("//input[@value='app-scim.userids']")).isSelected());
        Assert.assertTrue(webDriver.findElement(By.xpath("//input[@value='app-cloud_controller.read']")).isSelected());
        Assert.assertTrue(webDriver.findElement(By.xpath("//input[@value='app-cloud_controller.write']")).isSelected());

        // Add approvals
        webDriver.findElement(By.xpath("//input[@value='app-password.write']")).click();
        webDriver.findElement(By.xpath("//input[@value='app-scim.userids']")).click();

        webDriver.findElement(By.xpath("//button[text()='Update']")).click();

        Assert.assertTrue(webDriver.findElement(By.xpath("//input[@value='app-password.write']")).isSelected());
        Assert.assertTrue(webDriver.findElement(By.xpath("//input[@value='app-scim.userids']")).isSelected());
        Assert.assertTrue(webDriver.findElement(By.xpath("//input[@value='app-cloud_controller.read']")).isSelected());
        Assert.assertTrue(webDriver.findElement(By.xpath("//input[@value='app-cloud_controller.write']")).isSelected());

        // Revoke app
        webDriver.findElement(By.linkText("Revoke Access")).click();

        Assert.assertEquals("Are you sure you want to revoke access to The Ultimate Oauth App?", webDriver.findElement(By.cssSelector(".revocation-modal p")).getText());

        // click cancel
        webDriver.findElement(By.cssSelector("#app-form .revocation-cancel")).click();

        webDriver.findElement(By.linkText("Revoke Access")).click();

        // click confirm
        webDriver.findElement(By.cssSelector("#app-form .revocation-confirm")).click();

        Assert.assertThat(webDriver.findElements(By.xpath("//input[@value='app-password.write']")), Matchers.empty());
    }

    @Test
    public void testScopeDescriptions() {
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
        webDriver.get(appUrl);

        // Sign in to login server
        webDriver.findElement(By.name("username")).sendKeys(user.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(user.getPassword());
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        // Authorize the app for some scopes
        Assert.assertEquals("Application Authorization", webDriver.findElement(By.cssSelector("h1")).getText());

        webDriver.findElement(By.xpath("//label[text()='Read about <b>your</b> clouds.']/preceding-sibling::input"));
    }

    @Test
    public void testInvalidAppRedirectDisplaysError() {
        ScimUser user = createUnapprovedUser(serverRunning);

        // given we vist the app (specifying an invalid redirect - incorrect protocol https)
        webDriver.get(appUrl + "?redirect_uri=https://localhost:8080/app/");

        // Sign in to login server
        webDriver.findElement(By.name("username")).sendKeys(user.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(user.getPassword());
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        // Authorize the app for some scopes
        assertThat(webDriver.findElement(By.className("alert-error")).getText(), IntegrationTestUtils.RegexMatcher.matchesRegex("^Invalid redirect (.*) did not match one of the registered values"));
    }



}
