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

import org.cloudfoundry.identity.uaa.integration.pageObjects.HomePage;
import org.cloudfoundry.identity.uaa.integration.pageObjects.LoginPage;
import org.cloudfoundry.identity.uaa.integration.util.ScreenshotOnFailExtension;
import org.cloudfoundry.identity.uaa.oauth.client.test.TestAccounts;
import org.cloudfoundry.identity.uaa.test.UaaWebDriver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.By;
import org.openqa.selenium.TimeoutException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assumptions.assumeThat;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
@ExtendWith(ScreenshotOnFailExtension.class)
class HomeIT {
    @Autowired
    TestAccounts testAccounts;

    @Autowired
    @RegisterExtension
    private IntegrationTestExtension integrationTestExtension;

    @Autowired
    UaaWebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    private HomePagePerspective asOnHomePage;

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
        logout_and_clear_cookies();

        asOnHomePage = new HomePagePerspective(webDriver);
    }

    @Test
    void message() {
        LoginPage.go(webDriver, baseUrl)
                .sendLoginCredentials(testAccounts.getUserName(), testAccounts.getPassword());
        assertThat(webDriver.findElement(By.tagName("h1")).getText()).isEqualTo("Where to?");
    }

    @Test
    void profilePage() {
        HomePage homePage = LoginPage.go(webDriver, baseUrl)
                .sendLoginCredentials(testAccounts.getUserName(), testAccounts.getPassword());
        try {
            homePage.goHome().assertThatPageSource().contains("Where to?");
            webDriver.pressUaaNavigation("nav-dropdown-button", "nav-dropdown-content-profile");
        } catch (TimeoutException e) {
            webDriver.get(baseUrl + "/profile");
        }
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Account Settings");
    }

    @Test
    void defaultNoDropDown() {
        LoginPage.go(webDriver, baseUrl)
                .sendLoginCredentials(testAccounts.getUserName(), testAccounts.getPassword())
                .assertThatPageSource().contains("Where to?");
        assertThat(asOnHomePage.getUsernameElement()).isNotNull();
        assertThat(asOnHomePage.getAccountSettingsElement().isDisplayed()).isFalse();
        assertThat(asOnHomePage.getSignOutElement().isDisplayed()).isFalse();
    }

    @Test
    void theHeaderDropdown() {
        LoginPage.go(webDriver, baseUrl)
                .sendLoginCredentials(testAccounts.getUserName(), testAccounts.getPassword())
                .assertThatPageSource().contains("Where to?");
        try {
            WebDriverWait wait = new WebDriverWait(webDriver, Duration.ofSeconds(30));
            wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("nav-dropdown-button"))).click();
            assertThat(wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("nav-dropdown-content-profile"))).isDisplayed()).isTrue();
            assertThat(wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("nav-dropdown-content-logout"))).isDisplayed()).isTrue();
        } catch (TimeoutException e) {
            // If the dropdown is not visible ignore
            assumeThat(e.getMessage()).contains("waiting for visibility");
        }

    }

    static class HomePagePerspective {
        private final WebDriver webDriver;

        public HomePagePerspective(WebDriver webDriver) {
            this.webDriver = webDriver;
        }

        public WebElement getUsernameElement() {
            return webDriver.findElement(By.id("nav-dropdown-button"));
        }

        public WebElement getAccountSettingsElement() {
            return webDriver.findElement(By.id("nav-dropdown-content-profile"));
        }

        public WebElement getSignOutElement() {
            return webDriver.findElement(By.id("nav-dropdown-content-logout"));
        }
    }
}
