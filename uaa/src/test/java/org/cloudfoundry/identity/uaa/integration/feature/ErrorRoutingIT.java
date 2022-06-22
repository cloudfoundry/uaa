package org.cloudfoundry.identity.uaa.integration.feature;

import org.junit.*;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

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

    @Test
    public void testStatusCodeToErrorPage() throws IOException {
        CallErrorPageAndCheckHttpStatusCode("/error", 200);
        CallErrorPageAndCheckHttpStatusCode("/error404", 200);
        CallErrorPageAndCheckHttpStatusCode("/error500", 200);
        CallErrorPageAndCheckHttpStatusCode("/errorAny", 200);
        CallErrorPageAndCheckHttpStatusCode("/rejected", 200);
        CallErrorPageAndCheckHttpStatusCode("/saml_error", 200);

    }

    @Test
    public void testRequestRejectedExceptionErrorPage() throws IOException {
        final String rejectedEndpoint = "/login;endpoint=x"; // spring securiy throws RequestRejectedException and by default status 500, but now 400
        webDriver.get(baseUrl + rejectedEndpoint);

        Assert.assertTrue("Check if on the error page", webDriver.findElement(By.tagName("h2")).getText().contains("The request was rejected because it contained a potentially malicious character."));

        CallErrorPageAndCheckHttpStatusCode(rejectedEndpoint, 400);
    }

    private void CallErrorPageAndCheckHttpStatusCode(String errorPath, int codeExpected) throws IOException {
        HttpURLConnection cn = (HttpURLConnection)new URL(baseUrl + errorPath).openConnection();
        cn.setRequestMethod("GET");
        // connection initiate
        cn.connect();
        Assert.assertEquals("Check status code from " + errorPath + " is " + codeExpected, cn.getResponseCode(), codeExpected);
    }
}
