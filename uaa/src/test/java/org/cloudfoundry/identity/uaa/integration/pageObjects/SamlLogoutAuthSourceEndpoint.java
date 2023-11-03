package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.WebDriver;

public class SamlLogoutAuthSourceEndpoint extends Page {
    static final private String urlPath = "/module.php/core/logout";

    public SamlLogoutAuthSourceEndpoint(WebDriver driver) {
        super(driver);
    }

    static public SamlWelcomePage logoutAuthSource_goesToSamlWelcomePage(WebDriver driver, String baseUrl, String authSource) {
        driver.get(baseUrl + urlPath + "/" + authSource);
        return new SamlWelcomePage(driver);
    }
}

