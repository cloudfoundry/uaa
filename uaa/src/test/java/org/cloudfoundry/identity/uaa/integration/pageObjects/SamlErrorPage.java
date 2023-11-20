package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.WebDriver;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;

public class SamlErrorPage extends Page {
    static final private String urlPath = "/saml_error";

    public SamlErrorPage(WebDriver driver) {
        super(driver);
        validateUrl(driver, endsWith(urlPath));
    }
}

