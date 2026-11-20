package org.cloudfoundry.identity.uaa.integration.feature;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.xmlunit.assertj.XmlAssert;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
class ErrorRoutingIT {

    @Autowired
    @RegisterExtension
    private IntegrationTestExtension integrationTestExtension;

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Test
    void methodNotAllowedRoutedToErrorPage() {
        webDriver.get(baseUrl + "/authenticate");

        assertThat(webDriver.findElement(By.tagName("h2")).getText()).as("Check if on the error page").contains("Uh oh.")
                .as("Check if on the error page").contains("Something went amiss.");
    }

    @ParameterizedTest
    @CsvSource({
            "/error, 200",
            "/error404, 200",
            "/error429, 200",
            "/error500, 200",
            "/errorAny, 200",
            "/rejected, 400",
            "/saml_error, 200"
    })
    void statusCodeToErrorPage(String path, int expectedStatus) throws Exception {
        callErrorPageAndCheckHttpStatusCode(path, "GET", expectedStatus);
    }

    @Test
    void traceRequestsRejected() throws Exception {
        // org.springframework.security.web.firewall.StrictHttpFirewall rejects TRACE method
        HttpURLConnection cn = (HttpURLConnection) new URL(baseUrl + "/info").openConnection();
        cn.setRequestMethod("TRACE");

        try {
            assertThat(cn.getResponseCode())
                    .as("Check status code from TRACE method is 405")
                    .isEqualTo(405);
        } finally {
            cn.disconnect();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = { "/login?param=%00", "/login?param=val%00ue" } )
    void requestInvalidParameterErrorPage(String invalidParameter) throws Exception {
        String body = callErrorPageAndCheckHttpStatusCode(invalidParameter, "GET", 400);
        errorPage(body)
                .hasXPath("//p")
                .extractingText()
                .contains("The request contains an invalid parameter that can not be processed.");
    }

    @ParameterizedTest
    @ValueSource(strings = { "/login;endpoint=x", "/login;?endpoint=x", "/login?%00param=%00value" } )
    void requestRejectedExceptionErrorPage(String rejectedEndpoint) throws Exception {
        // spring security throws RequestRejectedException with status code 400
        String body = callErrorPageAndCheckHttpStatusCode(rejectedEndpoint, "GET", 400);
        errorPage(body)
                .hasXPath("//h2")
                .extractingText()
                .contains("The request was rejected because it contained a potentially malicious character.");
    }

    private XmlAssert errorPage(String body) {
        // Remove only the HTML5 declaration; keep XMLUnit's secure parser defaults intact.
        return XmlAssert.assertThat(body.replace("<!DOCTYPE html>", ""));
    }

    private String callErrorPageAndCheckHttpStatusCode(String errorPath, String method, int codeExpected) throws IOException {
        HttpURLConnection cn = (HttpURLConnection) new URL(baseUrl + errorPath).openConnection();
        cn.setRequestMethod(method);
        cn.setRequestProperty("Accept", "text/html");
        try {
            int status = cn.getResponseCode();
            assertThat(status).as("Check status code from %s is %s", errorPath, codeExpected).isEqualTo(codeExpected);
            try (InputStream body = status < 400 ? cn.getInputStream() : cn.getErrorStream()) {
                return new String(body.readAllBytes(), StandardCharsets.UTF_8);
            }
        } finally {
            cn.disconnect();
        }
    }
}
