package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.WebDriver;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.junit.Assert.assertThat;

public class PasscodePage extends Page {
    static final private String urlPath = "/passcode";

    public PasscodePage(WebDriver driver) {
        super(driver);
        validateUrl(driver, endsWith(urlPath));
        validatePageSource(driver, containsString("Temporary Authentication Code") );
    }

    static public LoginPage requestPasscode_goesToLoginPage(WebDriver driver, String baseUrl) {
        driver.get(baseUrl + urlPath);
        return new LoginPage(driver);
    }
}