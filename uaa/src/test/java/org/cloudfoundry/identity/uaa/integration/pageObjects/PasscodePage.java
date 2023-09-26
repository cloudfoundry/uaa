package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.WebDriver;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.junit.Assert.assertThat;

public class PasscodePage extends Page {
    static final protected String urlPath = "/passcode";

    static public LoginPage requestPasscode_goToLoginPage(WebDriver driver, String baseUrl) {
        driver.get(baseUrl + urlPath);
        return new LoginPage(driver);
    }

    public PasscodePage(WebDriver driver) {
        super(driver);
        validateUrl(driver, endsWith(urlPath));
        assertThat(driver.getPageSource(), containsString("Temporary Authentication Code"));
    }
}