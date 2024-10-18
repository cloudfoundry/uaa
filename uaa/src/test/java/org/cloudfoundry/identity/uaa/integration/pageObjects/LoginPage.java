package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import java.util.concurrent.atomic.AtomicReference;

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
        final AtomicReference<WebElement> matchingElement = new AtomicReference<>();
        driver.findElements(By.className("saml-login-link")).forEach(webElement -> {
            if (webElement.getText().contains(matchText)) {
                matchingElement.compareAndSet(null, webElement);
            }
        });
        if (matchingElement.get() == null) {
            throw new RuntimeException("No element with text " + matchText + " found");
        }
        matchingElement.get().click();
    }
}
