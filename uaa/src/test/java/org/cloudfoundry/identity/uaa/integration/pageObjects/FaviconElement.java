package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.WebDriver;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The FaviconElement class represents the favicon image on the UAA server.
 */
public class FaviconElement extends Page {

    /**
     * Expect a 404 error when landing on the favicon URL.
     */
    public FaviconElement(WebDriver driver) {
        super(driver);
        assertThat(driver.getCurrentUrl())
                .as("Should be on the favicon image")
                .endsWith("/favicon.ico");
        assertThat(driver.getPageSource())
                .contains("Something went amiss.");
    }

    /**
     * Get the default favicon image.
     * The favicon.ico image is not present on the server because we specify a custom icon URL
     * in the headers, but browsers try to hit it and tests need to hit this default URL.
     */
    static public FaviconElement getDefaultIcon(WebDriver driver, String baseUrl) {
        driver.get(baseUrl + "/favicon.ico");
        return new FaviconElement(driver);
    }
}
