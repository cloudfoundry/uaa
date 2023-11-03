package org.cloudfoundry.identity.uaa.integration.pageObjects;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.openqa.selenium.WebDriver;

public class LogoutDoEndpoint extends Page {
    static final private String urlPath = "/logout.do";


    public LogoutDoEndpoint(WebDriver driver) {
        super(driver);
    }

    static public LoginPage logout_goesToLoginPage(WebDriver driver, String baseUrl, String redirectUrl, String clientId) {
        driver.get(buildLogoutDoUrl(baseUrl, redirectUrl, clientId)
        );
        return new LoginPage(driver);
    }

    private static String buildLogoutDoUrl(String baseUrl, String redirectUrl, String clientId) {
        return baseUrl
                + urlPath
                + "?redirect=" + URLEncoder.encode(redirectUrl, StandardCharsets.UTF_8)
                + "&client_id=" + clientId;
    }
}

