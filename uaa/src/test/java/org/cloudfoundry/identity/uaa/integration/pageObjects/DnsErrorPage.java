package org.cloudfoundry.identity.uaa.integration.pageObjects;

import java.util.Date;

import org.openqa.selenium.WebDriver;

import static org.hamcrest.Matchers.containsString;

public class DnsErrorPage extends Page {
    static final protected String urlPath = "/";

    public DnsErrorPage(WebDriver driver) {
        super(driver);
        validatePageSource(driver, containsString("This site can’t be reached"));
    }
}

