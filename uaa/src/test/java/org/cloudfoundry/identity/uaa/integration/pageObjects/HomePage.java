package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.hamcrest.Matchers;
import org.openqa.selenium.WebDriver;
import org.opensaml.xml.encryption.Public;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.endsWith;

public class HomePage extends Page {
    public HomePage(WebDriver driver) {
        super(driver);
        assertThat("Should be on the home page", driver.getCurrentUrl(), endsWith("/"));
        assertThat(driver.getPageSource(), Matchers.containsString("Where to?"));
    }
}

