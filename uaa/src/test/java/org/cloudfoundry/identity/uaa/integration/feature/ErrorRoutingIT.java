package org.cloudfoundry.identity.uaa.integration.feature;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.xmlunit.assertj.XmlAssert;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

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

    @Test
    void statusCodeToErrorPage() throws IOException {
        CallErrorPageAndCheckHttpStatusCode("/error", "GET", 200);
        CallErrorPageAndCheckHttpStatusCode("/error404", "GET", 200);
        CallErrorPageAndCheckHttpStatusCode("/error429", "GET", 200);
        CallErrorPageAndCheckHttpStatusCode("/error500", "GET", 200);
        CallErrorPageAndCheckHttpStatusCode("/errorAny", "GET", 200);
        CallErrorPageAndCheckHttpStatusCode("/rejected", "GET", 400);
        CallErrorPageAndCheckHttpStatusCode("/saml_error", "GET", 200);
        CallErrorPageAndCheckHttpStatusCode("/error", "GET", 200);
    }

    @Test
    void traceRequestsRejected() throws IOException {
        // org.springframework.security.web.firewall.StrictHttpFirewall rejects TRACE method
        HttpURLConnection cn = (HttpURLConnection) new URL(baseUrl + "/info").openConnection();
        cn.setRequestMethod("TRACE");

        cn.connect();
        assertThat(cn.getResponseCode())
                .as("Check status code from TRACE method is 405")
                .isEqualTo(405);
    }

    @ParameterizedTest
    @ValueSource(strings = { "/login?param=%00", "/login?param=val%00ue" } )
    void requestInvalidParameterErrorPage(String invalidParameter) throws IOException {
        String body = CallErrorPageAndCheckHttpStatusCode(invalidParameter, "GET", 400);
        XmlAssert.assertThat(body)
                .hasXPath("//p")
                .extractingText()
                .contains("The request contains an invalid parameter that can not be processed.");
    }

    @ParameterizedTest
    @ValueSource(strings = { "/login;endpoint=x", "/login;?endpoint=x", "/login?%00param=%00value" } )
    void requestRejectedExceptionErrorPage(String rejectedEndpoint) throws IOException {
        // spring security throws RequestRejectedException with status code 400
        String body = CallErrorPageAndCheckHttpStatusCode(rejectedEndpoint, "GET", 400);
        XmlAssert.assertThat(body)
                .hasXPath("//h2")
                .extractingText()
                .contains("The request was rejected because it contained a potentially malicious character.");
    }

    private String CallErrorPageAndCheckHttpStatusCode(String errorPath, String method, int codeExpected) throws IOException {
        HttpURLConnection cn = (HttpURLConnection) new URL(baseUrl + errorPath).openConnection();
        cn.setRequestMethod(method);
        cn.setRequestProperty("Accept", "text/html");
        // connection initiate
        cn.connect();
        assertThat(cn.getResponseCode()).as("Check status code from " + errorPath + " is " + codeExpected).isEqualTo(codeExpected);
        return getResponseBody(cn);
    }

    private String getResponseBody(HttpURLConnection connection) throws IOException {
        BufferedReader reader;
        if (200 <= connection.getResponseCode() && connection.getResponseCode() <= 299) {
            reader = new BufferedReader(new InputStreamReader((connection.getInputStream())));
        } else {
            reader = new BufferedReader(new InputStreamReader((connection.getErrorStream())));
        }

        StringBuilder sb = new StringBuilder();
        int bufferSize = 4096;
        char[] buffer = new char[bufferSize];
        int charsRead = 0;
        try {
            while ((charsRead = reader.read(buffer, 0, bufferSize)) != -1) {
                sb.append(buffer, 0, charsRead);
            }
        } catch (IOException ie) {
            IOUtils.close(connection);
        }
        return sb.toString();
    }
}
