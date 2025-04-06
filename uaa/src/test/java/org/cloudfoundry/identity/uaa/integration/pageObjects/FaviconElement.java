package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.cloudfoundry.identity.uaa.test.UaaWebDriver;

/**
 * The FaviconElement class represents the favicon image on the UAA server.
 */
public class FaviconElement extends Page {

    private static final String FAVICON_ICO = "/favicon.ico";

    /**
     * Expect a 404 error when landing on the favicon URL.
     */
    public FaviconElement(UaaWebDriver driver) {
        super(driver);
        assertThatUrlEventuallySatisfies(assertUrl -> assertUrl.as("Should be on the favicon image").endsWith(FAVICON_ICO));
        assertThatPageSource().contains("Something went amiss.");
    }

    /**
     * Get the default favicon image.
     * The favicon.ico image is not present on the server because we specify a custom icon URL
     * in the headers, but browsers try to hit it and tests need to hit this default URL.
     */
    public static FaviconElement getDefaultIcon(UaaWebDriver driver, String baseUrl) {
        driver.get(baseUrl + FAVICON_ICO);
        return new FaviconElement(driver);
    }
}
