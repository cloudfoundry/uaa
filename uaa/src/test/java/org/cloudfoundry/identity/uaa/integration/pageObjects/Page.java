package org.cloudfoundry.identity.uaa.integration.pageObjects;

import java.time.Duration;

import org.hamcrest.Matcher;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

import static org.junit.Assert.assertThat;

public class Page {
    protected WebDriver driver;

    public Page(WebDriver driver) {
        this.driver = driver;
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(5));
    }

    protected static void validateUrl(WebDriver driver, Matcher urlMatcher) {
        assertThat("URL validation failed", driver.getCurrentUrl(), urlMatcher);
    }

    public void validateUrl(Matcher urlMatcher) {
        validateUrl(driver, urlMatcher);
    }

    protected static void validatePageSource(WebDriver driver, Matcher matcher) {
        assertThat(driver.getPageSource(), matcher);
    }

    public void validatePageSource(Matcher matcher) {
        validatePageSource(driver, matcher);
    }

    public void validateTitle(Matcher matcher) {
        assertThat(driver.getTitle(), matcher);
    }

    public LoginPage logout_goesToLoginPage() {
        clickLogout();
        return new LoginPage(driver);
    }

    private void clickLogout() {
        driver.findElement(By.cssSelector(".dropdown-trigger")).click();
        driver.findElement(By.linkText("Sign Out")).click();
    }

    public void clearCookies() {
        driver.manage().deleteAllCookies();
    }
}
