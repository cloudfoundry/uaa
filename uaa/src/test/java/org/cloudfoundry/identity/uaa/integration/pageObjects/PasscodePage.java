package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.WebDriver;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.junit.Assert.assertThat;

public class PasscodePage extends Page {

    static public LoginPage requestPasscode_goToLoginPage(WebDriver driver, String baseUrl) {
        driver.get(baseUrl + "/passcode");
        return new LoginPage(driver);
    }

    public PasscodePage(WebDriver driver) {
        super(driver);
        assertThat("Should be on the passcode page", driver.getCurrentUrl(), endsWith("/passcode"));
        assertThat(driver.getPageSource(), containsString("Temporary Authentication Code"));
    }
}