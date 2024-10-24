package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.WebDriver;

/**
 * The SamlErrorPage class represents the saml error page on the UAA server.
 * It has url matching: `/saml_error`.
 */
public class SamlErrorPage extends Page {
    private static final String URL_PATH = "/saml_error";

    public SamlErrorPage(WebDriver driver) {
        super(driver);
        assertThatUrlEventuallySatisfies(assertUrl -> assertUrl.endsWith(URL_PATH));
    }
}
