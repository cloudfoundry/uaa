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
package org.cloudfoundry.identity.uaa.login.feature;

import org.cloudfoundry.identity.uaa.login.test.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.login.test.IntegrationTestRule;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class AppApprovalIT {

    @Autowired @Rule
    public IntegrationTestRule integrationTestRule;

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Value("${integration.test.app_url}")
    String appUrl;
    
    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(null);

    @Test
    public void testApprovingAnApp() throws Exception {
        webDriver.get(baseUrl + "/logout.do");

        // Visit app
        webDriver.get(appUrl);

        // Sign in to login server
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(testAccounts.getPassword());
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        // Authorize the app for some scopes
        Assert.assertEquals("Application Authorization", webDriver.findElement(By.cssSelector("h1")).getText());

        webDriver.findElement(By.xpath("//label[text()='Change your password']/preceding-sibling::input")).click();
        webDriver.findElement(By.xpath("//label[text()='Translate user ids to names and vice versa']/preceding-sibling::input")).click();

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

        Assert.assertEquals("Are you sure you want to revoke access to app?", webDriver.findElement(By.cssSelector(".revocation-modal p")).getText());

        // click cancel
        webDriver.findElement(By.cssSelector("#app-form .revocation-cancel")).click();

        webDriver.findElement(By.linkText("Revoke Access")).click();

        // click confirm
        webDriver.findElement(By.cssSelector("#app-form .revocation-confirm")).click();

        Assert.assertThat(webDriver.findElements(By.xpath("//input[@value='app-password.write']")), Matchers.empty());
    }
}
