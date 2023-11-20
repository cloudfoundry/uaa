package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

import static org.hamcrest.Matchers.matchesPattern;

public class LoginPage extends Page {

    static final private String urlPath = "/login";

    public LoginPage(WebDriver driver) {
        super(driver);
        validateUrl(driver, matchesPattern(".*" + urlPath + "(\\?.*)?$"));
    }

    static public LoginPage go(WebDriver driver, String baseUrl) {
        driver.get(baseUrl + urlPath);
        return new LoginPage(driver);
    }

    // When there is a SAML integration, there is a link to go to a SAML login page instead. This assumes there is
    // only one SAML link.
    public SamlLoginPage clickSamlLink_goesToSamlLoginPage() {
        clickFirstSamlLoginLink();
        return new SamlLoginPage(driver);
    }

    // If the SAML IDP has no logout URL in the metadata, logging out of UAA will leave
    // the IDP still logged in, and when going back to the SAML login page, it will log
    // the app back in automatically and immediately redirect to the post-login page.
    public HomePage clickSamlLink_goesToHomePage() {
        clickFirstSamlLoginLink();
        return new HomePage(driver);
    }

    private void clickFirstSamlLoginLink() {
        driver.findElement(By.className("saml-login-link")).click();
    }
}