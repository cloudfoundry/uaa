package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;

public class SamlLogoutAuthSourceEndpoint extends Page {
    static final protected String urlPath = "/module.php/core/logout";

    public SamlLogoutAuthSourceEndpoint(WebDriver driver) {
        super(driver);
    }

    static public SamlWelcomePage logoutAuthSource_goToSamlWelcomePage(WebDriver driver, String baseUrl, String authSource) {
        driver.get(baseUrl + urlPath + "/" + authSource);
        return new SamlWelcomePage(driver);
    }
}

