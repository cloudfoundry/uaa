package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.WebDriver;

public class SamlErrorPage extends Page {
    static final private String urlPath = "/saml_error";

    public SamlErrorPage(WebDriver driver) {
        super(driver);
        assertThatUrlEventuallySatisfies(assertUrl -> assertUrl.endsWith(urlPath));
    }
}

