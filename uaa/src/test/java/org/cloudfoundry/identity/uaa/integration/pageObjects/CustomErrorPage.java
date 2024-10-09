package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.hamcrest.Matcher;
import org.openqa.selenium.WebDriver;

/**
 * The CustomErrorPage class represents the custom error page on the UAA server.
 */
public class CustomErrorPage extends Page {

    public CustomErrorPage(WebDriver driver, Matcher<String> urlMatcher) {
        super(driver);
        validateUrl(driver, urlMatcher);
    }
}
