package org.cloudfoundry.identity.uaa.integration.endpoints;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.cloudfoundry.identity.uaa.integration.pageObjects.SamlLoginPage;
import org.openqa.selenium.WebDriver;

public class OauthAuthorizeEndpoint {
    static final private String urlPath = "/oauth/authorize";

    static public SamlLoginPage authorize_goesToSamlLoginPage(WebDriver driver, String baseUrl, String redirectUri, String clientId, String response_type) {
        driver.get(buildAuthorizeUrl(baseUrl, redirectUri, clientId, response_type));
        return new SamlLoginPage(driver);
    }

    private static String buildAuthorizeUrl(String baseUrl, String redirectUri, String clientId, String response_type) {
        return baseUrl
                + urlPath
                + "?client_id=" + clientId
                + "&response_type=" + response_type
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);
    }
}
