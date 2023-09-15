package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.hamcrest.Matchers;
import org.joda.time.DateTime;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.opensaml.xml.encryption.Public;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.endsWith;
import static org.junit.Assert.assertNotNull;

public class HomePage extends Page {
    public HomePage(WebDriver driver) {
        super(driver);
        assertThat("Should be on the home page", driver.getCurrentUrl(), endsWith("/"));
        assertThat(driver.getPageSource(), Matchers.containsString("Where to?"));
    }

    public boolean hasLastLoginTime() {
        WebElement lastLoginTime = driver.findElement(By.id("last_login_time"));
        String loginTime = lastLoginTime.getText();
        return loginTime != null && ! loginTime.isBlank();
    }
}

