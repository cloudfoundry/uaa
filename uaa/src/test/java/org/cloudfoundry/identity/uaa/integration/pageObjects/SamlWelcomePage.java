package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;

public class SamlWelcomePage extends Page {
    static final private String urlPath = "module.php/core/welcome";

    public SamlWelcomePage(WebDriver driver) {
        super(driver);
        validateUrl(driver, endsWith(urlPath));
    }

}

