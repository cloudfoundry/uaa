package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.hamcrest.Matcher;
import org.openqa.selenium.WebDriver;

public class CustomErrorPage extends Page {

    public CustomErrorPage(WebDriver driver, Matcher urlMatcher) {
        super(driver);
        validateUrl(driver, urlMatcher);
    }
}

