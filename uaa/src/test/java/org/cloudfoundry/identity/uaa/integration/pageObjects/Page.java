package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.hamcrest.Matcher;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

import static org.junit.Assert.assertThat;

public class Page {
    protected WebDriver driver;

    public Page(WebDriver driver) {
        this.driver = driver;
    }

    protected static void validateUrl(WebDriver driver, Matcher urlMatcher) {
        assertThat("URL validation failed", driver.getCurrentUrl(), urlMatcher);
    }

    protected static void validatePageSource(WebDriver driver, Matcher matcher) {
        assertThat(driver.getPageSource(), matcher);
    }

    public LoginPage logout_goToLoginPage() {
        clickLogout();
        return new LoginPage(driver);
    }

    private void clickLogout() {
        driver.findElement(By.cssSelector(".dropdown-trigger")).click();
        driver.findElement(By.linkText("Sign Out")).click();
    }
}
