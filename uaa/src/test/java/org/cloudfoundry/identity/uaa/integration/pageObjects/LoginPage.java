package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

import static org.hamcrest.Matchers.endsWith;
import static org.junit.Assert.assertThat;

public class LoginPage extends Page {
    public LoginPage(WebDriver driver) {
        super(driver);
        assertThat("Should be on the login page", driver.getCurrentUrl(), endsWith("/login"));
    }

    // When there is a SAML integration, there is a link to go to a SAML login page instead. This assumes there is
    // only one SAML link.
    public SamlLoginPage startSamlLogin() {
        driver.findElement(By.className("saml-login-link")).click();
        return new SamlLoginPage(driver);
    }
}