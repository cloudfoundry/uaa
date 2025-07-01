package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.WebDriver;

import static org.hamcrest.Matchers.containsString;

public class PasscodePage extends Page {
    static final private String urlPath = "/passcode";

    public PasscodePage(WebDriver driver) {
        super(driver);
        assertThatUrlEventuallySatisfies(assertUrl -> assertUrl.endsWith(urlPath));
        validatePageSource(driver, containsString("Temporary Authentication Code") );
    }

    static public LoginPage requestPasscode_goesToLoginPage(WebDriver driver, String baseUrl) {
        driver.get(baseUrl + urlPath);
        return new LoginPage(driver);
    }
}