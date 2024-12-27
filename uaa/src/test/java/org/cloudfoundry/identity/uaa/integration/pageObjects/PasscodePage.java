package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.WebDriver;

/**
 * The PasscodePage class represents the passcode page on the UAA server.
 * Which displays the temporary authentication code.
 * It has url matching: `/passcode`.
 */
public class PasscodePage extends Page {
    private static final String URL_PATH = "/passcode";

    public PasscodePage(WebDriver driver) {
        super(driver);
        assertThatUrlEventuallySatisfies(assertUrl -> assertUrl.endsWith(URL_PATH));
        assertThatPageSource().contains("Temporary Authentication Code");
    }

    public static LoginPage assertThatRequestPasscode_goesToLoginPage(WebDriver driver, String baseUrl) {
        driver.get(baseUrl + URL_PATH);
        return new LoginPage(driver);
    }
}
