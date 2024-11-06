package org.cloudfoundry.identity.uaa.integration.endpoints;

import org.cloudfoundry.identity.uaa.integration.pageObjects.SamlLoginPage;
import org.openqa.selenium.WebDriver;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class OauthAuthorizeEndpoint {
    private static final String URL_PATH = "/oauth/authorize";

    public static SamlLoginPage assertThatAuthorize_goesToSamlLoginPage(WebDriver driver, String baseUrl, String redirectUri, String clientId, String responseType) {
        driver.get(buildAuthorizeUrl(baseUrl, redirectUri, clientId, responseType));
        return new SamlLoginPage(driver);
    }

    private static String buildAuthorizeUrl(String baseUrl, String redirectUri, String clientId, String responseType) {
        return baseUrl
                + URL_PATH
                + "?client_id=" + clientId
                + "&response_type=" + responseType
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);
    }
}
