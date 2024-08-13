package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.WebDriver;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;

/**
 * The PasscodePage class represents the passcode page on the UAA server.
 * Which displays the temporary authentication code.
 * It has url matching: `/passcode`.
 */
public class PasscodePage extends Page {
    private static final String URL_PATH = "/passcode";

    public PasscodePage(WebDriver driver) {
        super(driver);
        validateUrl(driver, endsWith(URL_PATH));
        validatePageSource(driver, containsString("Temporary Authentication Code"));
    }

    public static LoginPage requestPasscode_goesToLoginPage(WebDriver driver, String baseUrl) {
        driver.get(baseUrl + URL_PATH);
        return new LoginPage(driver);
    }
}
