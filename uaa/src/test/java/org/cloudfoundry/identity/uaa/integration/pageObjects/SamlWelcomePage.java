package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.cloudfoundry.identity.uaa.integration.feature.SamlServerConfig;
import org.openqa.selenium.WebDriver;

/**
 * The SamlWelcomePage class represents the welcome page on the SimpleSAML server.
 * It has url matching: `/module.php/core/welcome`.
 */
public class SamlWelcomePage extends Page {


    public SamlWelcomePage(WebDriver webDriver, SamlServerConfig samlServerConfig) {
        super(webDriver);
        assertThatUrlEventuallySatisfies(assertUrl -> assertUrl.endsWith(samlServerConfig.getWelcomePath()));

    }
}
