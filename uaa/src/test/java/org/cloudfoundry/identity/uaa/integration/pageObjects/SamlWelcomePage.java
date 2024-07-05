package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.WebDriver;

import static org.hamcrest.Matchers.endsWith;

/**
 * The SamlWelcomePage class represents the welcome page on the SimpleSAML server.
 * It has url matching: `/module.php/core/welcome`.
 */
public class SamlWelcomePage extends Page {
    static final private String urlPath = "module.php/core/welcome";

    public SamlWelcomePage(WebDriver driver) {
        super(driver);
        validateUrl(driver, endsWith(urlPath));
    }
}
