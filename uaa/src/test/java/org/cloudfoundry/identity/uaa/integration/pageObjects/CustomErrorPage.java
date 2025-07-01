package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.WebDriver;

public class CustomErrorPage extends Page {

    public CustomErrorPage(WebDriver driver, String urlContent) {
        super(driver);
        assertThatUrlEventuallySatisfies(assertUrl -> assertUrl.contains(urlContent));
    }
}

