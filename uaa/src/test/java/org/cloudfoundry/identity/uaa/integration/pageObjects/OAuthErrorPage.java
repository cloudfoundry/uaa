package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

/**
 * The OAuthErrorPage class represents the external OAuth authentication error page on the UAA server.
 * It has url matching: {@code /oauth_error}.
 */
public class OAuthErrorPage extends Page {

    private static final String URL_PATH = "/oauth_error";

    public OAuthErrorPage(WebDriver driver) {
        super(driver);
        assertThatUrlEventuallySatisfies(assertUrl -> assertUrl.contains(URL_PATH));
    }

    /**
     * Asserts that the page displays the user-friendly "concurrent login" message shown when
     * the state parameter from an older browser tab's IDP callback no longer matches the
     * session's current state (because a newer login attempt replaced it).
     */
    public OAuthErrorPage assertConcurrentLoginMessageShown() {
        assertThatPageSource().contains("Another sign-in is already in progress");
        return this;
    }

    /**
     * Asserts that the page provides a link to restart the login flow.
     */
    public OAuthErrorPage assertRestartLoginLinkPresent() {
        assertThatPageSource().contains("Start a new login");
        return this;
    }

    /**
     * Clicks the "Start a new login" link and returns the resulting LoginPage.
     */
    public LoginPage clickStartNewLogin(String baseUrl) {
        driver.findElement(By.linkText("Start a new login")).click();
        return new LoginPage(driver, baseUrl);
    }
}
