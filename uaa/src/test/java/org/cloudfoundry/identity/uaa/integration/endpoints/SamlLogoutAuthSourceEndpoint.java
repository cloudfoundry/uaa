package org.cloudfoundry.identity.uaa.integration.endpoints;

import org.cloudfoundry.identity.uaa.integration.pageObjects.Page;
import org.cloudfoundry.identity.uaa.integration.pageObjects.SamlWelcomePage;
import org.openqa.selenium.WebDriver;

public class SamlLogoutAuthSourceEndpoint {
    static final private String urlPath = "/module.php/core/logout";

    static public SamlWelcomePage logoutAuthSource_goesToSamlWelcomePage(WebDriver driver, String baseUrl, String authSource) {
        driver.get(baseUrl + urlPath + "/" + authSource);
        return new SamlWelcomePage(driver);
    }
}

