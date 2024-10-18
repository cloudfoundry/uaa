package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.WebDriver;

/**
 * The CustomErrorPage class represents the custom error page on the UAA server.
 */
public class CustomErrorPage extends Page {

    public CustomErrorPage(WebDriver driver, String urlContent) {
        super(driver);
        assertThatUrlEventuallySatisfies(assertUrl -> assertUrl.contains(urlContent));
    }
}
