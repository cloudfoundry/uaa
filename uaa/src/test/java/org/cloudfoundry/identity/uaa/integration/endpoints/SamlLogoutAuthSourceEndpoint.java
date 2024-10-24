package org.cloudfoundry.identity.uaa.integration.endpoints;

import org.cloudfoundry.identity.uaa.integration.pageObjects.SamlWelcomePage;
import org.openqa.selenium.WebDriver;

public class SamlLogoutAuthSourceEndpoint {
    private static final String URL_PATH = "/module.php/core/logout";

    public static SamlWelcomePage assertThatLogoutAuthSource_goesToSamlWelcomePage(WebDriver driver, String baseUrl, String authSource) {
        driver.get(baseUrl + URL_PATH + "/" + authSource);
        return new SamlWelcomePage(driver);
    }
}
