package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.cloudfoundry.identity.uaa.test.UaaWebDriver;

/**
 * The SamlErrorPage class represents the saml error page on the UAA server.
 * It has url matching: `/saml_error`.
 */
public class SamlErrorPage extends Page {
    private static final String URL_PATH = "/saml_error";

    public SamlErrorPage(UaaWebDriver driver) {
        super(driver);
        assertThatUrlEventuallySatisfies(assertUrl -> assertUrl.endsWith(URL_PATH));
    }
}
