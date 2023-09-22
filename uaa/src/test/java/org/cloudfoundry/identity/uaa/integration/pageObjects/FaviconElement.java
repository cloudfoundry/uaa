package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.hamcrest.Matchers;
import org.openqa.selenium.WebDriver;

import static org.hamcrest.Matchers.endsWith;
import static org.junit.Assert.assertThat;

public class FaviconElement extends Page {

    // The favicon.ico URL is not present on the server because we specify a custom icon URL
    // in the headers, but browsers try to hit it and tests need to hit this default URL.
    static public FaviconElement getDefaultIcon(WebDriver driver, String baseUrl) {
        driver.get(baseUrl + "/favicon.ico");
        return new FaviconElement(driver);
    }

    // Expect a 404 error when landing on the favicon URL.
    public FaviconElement(WebDriver driver) {
        super(driver);
        assertThat("Should be on the favicon image", driver.getCurrentUrl(), endsWith("/favicon.ico"));
        assertThat(driver.getPageSource(), Matchers.containsString("Something went amiss."));
    }
}