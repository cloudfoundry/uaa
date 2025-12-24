package org.cloudfoundry.identity.uaa.integration;

import org.cloudfoundry.identity.uaa.integration.feature.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.integration.feature.TestClient;
import org.cloudfoundry.identity.uaa.oauth.client.test.TestAccounts;
import org.cloudfoundry.identity.uaa.test.UaaWebDriver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import static org.assertj.core.api.Assertions.assertThat;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
class SessionControllerIntegrationTests {
    @Autowired
    TestClient testClient;
    @Autowired
    TestAccounts testAccounts;
    @Autowired
    UaaWebDriver webDriver;
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
    void sessionPageHasTheFunction() {
        webDriver.get(baseUrl +
                "/session?clientId=admin&messageOrigin=http://localhost:8080");

        WebDriverWait wait = webDriver.createWebDriverWait();
        Object type = wait.until(driver -> webDriver.getJavascriptExecutor().executeScript(
                "return typeof(handleMessage);"));

        assertThat(type).hasToString("function");
    }

    @Test
    void sessionManagementPageHasVariablesSet() {
        webDriver.get(baseUrl +
                "/session_management?clientId=admin&messageOrigin=http://localhost:8080");

        // Use WebDriverWait to wait for the variable to exist (prevents race conditions)
        // return null instead of crashing if undefined (better assertion handling)
        WebDriverWait wait = webDriver.createWebDriverWait();
        Object clientId = wait.until(driver -> webDriver.getJavascriptExecutor().executeScript(
                "return (typeof clientId !== 'undefined') ? clientId : null;"));

        assertThat(clientId).as("Global variable 'clientId' should match URL param")
                .hasToString("admin");

        Object origin = wait.until(driver -> webDriver.getJavascriptExecutor().executeScript(
                "return (typeof messageOrigin !== 'undefined') ? messageOrigin : null;"));

        assertThat(origin).as("Global variable 'messageOrigin' should match URL param")
                .hasToString("http://localhost:8080");
    }
}
