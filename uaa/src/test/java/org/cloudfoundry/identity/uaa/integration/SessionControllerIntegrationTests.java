package org.cloudfoundry.identity.uaa.integration;

import org.cloudfoundry.identity.uaa.integration.feature.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.integration.feature.TestClient;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class SessionControllerIntegrationTests {
    @Autowired
    TestClient testClient;
    @Autowired
    TestAccounts testAccounts;
    @Autowired
    WebDriver webDriver;
    @Value("${integration.test.base_url}")
    String baseUrl;

    @BeforeEach
    @AfterEach
    public void logout_and_clear_cookies() {
        try {
            webDriver.get(baseUrl + "/logout.do");
        }catch (org.openqa.selenium.TimeoutException x) {
            //try again - this should not be happening - 20 second timeouts
            webDriver.get(baseUrl + "/logout.do");
        }
        webDriver.manage().deleteAllCookies();
    }

    @Test
    public void sessionPageHasTheFunction() {
        webDriver.get(baseUrl +
                "/session?clientId=admin&messageOrigin=http://localhost:8080");

        Object r = ((JavascriptExecutor)webDriver).executeScript(
                "return typeof(handleMessage);");
        assertEquals("function", r.toString());
    }

    @Test
    public void sessionManagementPageHasVariablesSet() {
        webDriver.get(baseUrl +
                "/session_management?clientId=admin&messageOrigin=http://localhost:8080");

        Object origin = ((JavascriptExecutor)webDriver).executeScript(
                "return origin;");
        assertEquals("http://localhost:8080", origin.toString());

        Object clientId = ((JavascriptExecutor)webDriver).executeScript(
                "return clientId;");
        assertEquals("admin", clientId.toString());
    }
}
