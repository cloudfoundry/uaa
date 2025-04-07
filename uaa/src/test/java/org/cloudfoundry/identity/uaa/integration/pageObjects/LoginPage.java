package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.cloudfoundry.identity.uaa.test.UaaWebDriver;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

/**
 * The LoginPage class represents the login page on the UAA server.
 * It has url matching: `/login`.
 */
public class LoginPage extends Page {

    private static final String URL_PATH = "/login";

    public LoginPage(WebDriver driver) {
        super(driver);
        assertThatUrlEventuallySatisfies(assertUrl -> assertUrl.matches(".*" + URL_PATH + "(\\?.*)?$"));
    }

    public static LoginPage go(WebDriver driver, String baseUrl) {
        driver.get(baseUrl + URL_PATH);
        return new LoginPage(driver);
    }

    /**
     * When there is a SAML integration, there is a link to go to a SAML login page.
     * Clicking the link will go to the SAML login page.
     */
    public SamlLoginPage assertThatSamlLink_goesToSamlLoginPage(String matchText) {
        clickSamlLoginLinkWithText(matchText);
        return new SamlLoginPage(driver);
    }

    /**
     * If the SAML IDP has no logout URL in the metadata, logging out of UAA will leave
     * the IDP still logged in.
     * When going back to the SAML login page, it will log
     * the app back in automatically and immediately redirect to the post-login page.
     */
    public HomePage assertThatSamlLink_goesToHomePage(String matchText) {
        clickSamlLoginLinkWithText(matchText);
        return new HomePage(driver);
    }

    /**
     * Click the first link that contains the given text
     */
    private void clickSamlLoginLinkWithText(String matchText) {
        UaaWebDriver uaaWebDriver = (UaaWebDriver) driver;
        uaaWebDriver.clickAndWait(By.linkText(matchText));
    }
}
