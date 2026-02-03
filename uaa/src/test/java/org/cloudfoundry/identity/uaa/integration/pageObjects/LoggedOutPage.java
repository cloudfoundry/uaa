package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.cloudfoundry.identity.uaa.test.UaaWebDriver;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

import static org.assertj.core.api.Assertions.assertThat;

public class LoggedOutPage extends Page {
    private static final String URL_PATH = "/logged_out";
    private static final String EXPECTED_HEADING = "You have successfully logged out.";

    private static final By HEADING_SELECTOR = By.cssSelector("h1");
    private static final By BACK_TO_SIGN_IN_LINK_SELECTOR = By.linkText("Back to Sign In");

    public LoggedOutPage(final WebDriver driver, final String baseUrl) {
        super(driver, baseUrl);
        assertThatLoggedOutPageShown();
    }

    public static LoggedOutPage go(final WebDriver driver, final String baseUrl) {
        driver.get(baseUrl + URL_PATH);
        return null;
    }

    private void assertThatLoggedOutPageShown() {
        // check path
        if (baseUrl == null) {
            assertThatUrlEventuallySatisfies(assertUrl -> assertUrl.matches(".*" + URL_PATH));
        } else {
            assertThatUrlEventuallySatisfies(assertUrl -> assertUrl.endsWith(baseUrl + URL_PATH));
        }

        // check heading
        assertThat(driver.findElement(HEADING_SELECTOR).getText()).contains(EXPECTED_HEADING);

        // check link text
        assertThat(driver.findElement(BACK_TO_SIGN_IN_LINK_SELECTOR).getAttribute("href"))
                .isEqualTo(baseUrl + "/login");
    }

    public LoginPage assertThatBackToSignInLink_goesToLoginPage(final String baseUrl) {
        ((UaaWebDriver) driver).clickAndWait(BACK_TO_SIGN_IN_LINK_SELECTOR);
        return new LoginPage(driver, baseUrl);
    }
}
