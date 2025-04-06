package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.cloudfoundry.identity.uaa.test.UaaWebDriver;

/**
 * The PasscodePage class represents the passcode page on the UAA server.
 * Which displays the temporary authentication code.
 * It has url matching: `/passcode`.
 */
public class PasscodePage extends Page {
    private static final String URL_PATH = "/passcode";

    public PasscodePage(UaaWebDriver driver) {
        super(driver);
        assertThatUrlEventuallySatisfies(assertUrl -> assertUrl.endsWith(URL_PATH));
        assertThatPageSource().contains("Temporary Authentication Code");
    }

    public static LoginPage assertThatRequestPasscode_goesToLoginPage(UaaWebDriver driver, String baseUrl) {
        driver.get(baseUrl + URL_PATH);
        return new LoginPage(driver);
    }
}
