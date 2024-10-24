package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.WebDriver;

/**
 * The SamlWelcomePage class represents the welcome page on the SimpleSAML server.
 * It has url matching: `/module.php/core/welcome`.
 */
public class SamlWelcomePage extends Page {
    private static final String URL_PATH = "module.php/core/welcome";

    public SamlWelcomePage(WebDriver driver) {
        super(driver);
        assertThatUrlEventuallySatisfies(assertUrl -> assertUrl.endsWith(URL_PATH));
    }
}
