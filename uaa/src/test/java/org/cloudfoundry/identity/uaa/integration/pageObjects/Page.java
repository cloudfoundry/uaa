package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.assertj.core.api.HamcrestCondition;
import org.hamcrest.Matcher;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The Page class is the base class, representing a web page.
 * It provides methods for validating the URL, page source, and title,
 * as well as performing common page actions like logging out and clearing cookies.
 */
public class Page {
    protected WebDriver driver;

    public Page(WebDriver driver) {
        this.driver = driver;
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(5));
    }

    protected static void validateUrl(WebDriver driver, Matcher<String> urlMatcher) {
        HamcrestCondition<String> condition = new HamcrestCondition<>(urlMatcher);
        assertThat(driver.getCurrentUrl()).as("URL validation failed").is(condition);
    }

    protected static void validatePageSource(WebDriver driver, Matcher<String> matcher) {
        HamcrestCondition<String> condition = new HamcrestCondition<>(matcher);
        assertThat(driver.getPageSource()).is(condition);
    }

    public void validateUrl(Matcher<String> urlMatcher) {
        validateUrl(driver, urlMatcher);
    }

    public void validatePageSource(Matcher<String> matcher) {
        validatePageSource(driver, matcher);
    }

    public void validateTitle(Matcher<String> matcher) {
        HamcrestCondition<String> condition = new HamcrestCondition<>(matcher);
        assertThat(driver.getTitle()).is(condition);
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

    public static void validateUrlStartsWithWait(WebDriver driver, String currentUrlStart) throws InterruptedException {
        if (!driver.getCurrentUrl().startsWith(currentUrlStart)) {
            TimeUnit.SECONDS.sleep(5);
        }
        assertThat(driver.getCurrentUrl()).startsWith(currentUrlStart);
    }
}
