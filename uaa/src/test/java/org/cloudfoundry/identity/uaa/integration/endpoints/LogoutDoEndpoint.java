package org.cloudfoundry.identity.uaa.integration.endpoints;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.cloudfoundry.identity.uaa.integration.pageObjects.LoginPage;
import org.cloudfoundry.identity.uaa.integration.pageObjects.Page;
import org.openqa.selenium.WebDriver;

public class LogoutDoEndpoint {
    private static final String urlPath = "/logout.do";

    public static LoginPage logout_goesToLoginPage(WebDriver driver, String baseUrl, String redirectUrl, String clientId) {
        driver.get(buildLogoutDoUrl(baseUrl, redirectUrl, clientId));
        return new LoginPage(driver);
    }

    public static void logout(WebDriver driver, String baseUrl) {
        driver.get(baseUrl + urlPath);
    }

    private static String buildLogoutDoUrl(String baseUrl, String redirectUrl, String clientId) {
        return baseUrl
                + urlPath
                + "?redirect=" + URLEncoder.encode(redirectUrl, StandardCharsets.UTF_8)
                + "&client_id=" + clientId;
    }
}

