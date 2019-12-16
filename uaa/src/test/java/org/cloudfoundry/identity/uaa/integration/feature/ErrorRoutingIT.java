package org.cloudfoundry.identity.uaa.integration.feature;

import org.junit.*;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class ErrorRoutingIT {

    @Autowired
    @Rule
    public IntegrationTestRule integrationTestRule;

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Test
    public void testMethodNotAllowedRoutedToErrorPage() {
        webDriver.get(baseUrl + "/authenticate");

        Assert.assertTrue("Check if on the error page", webDriver.findElement(By.tagName("h2")).getText().contains("Uh oh."));
        Assert.assertTrue("Check if on the error page", webDriver.findElement(By.tagName("h2")).getText().contains("Something went amiss."));
    }
}
