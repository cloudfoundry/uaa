package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.cloudfoundry.identity.uaa.test.UaaWebDriver;

/**
 * The CustomErrorPage class represents the custom error page on the UAA server.
 */
public class CustomErrorPage extends Page {

    public CustomErrorPage(UaaWebDriver driver, String urlContent) {
        super(driver);
        assertThatUrlEventuallySatisfies(assertUrl -> assertUrl.contains(urlContent));
    }
}
