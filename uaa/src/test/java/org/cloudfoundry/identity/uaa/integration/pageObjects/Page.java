package org.cloudfoundry.identity.uaa.integration.pageObjects;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

import org.hamcrest.Matcher;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertThat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import org.assertj.core.api.AbstractStringAssert;

import java.util.function.Consumer;

public class Page {
    // This is used to control the max time that awaitility will check to see if
    // an assertion passes, before failing the test.
    protected static final Duration AWAIT_AT_MOST_SECONDS = Duration.ofSeconds(30);

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

    private static AbstractStringAssert<?> assertThatUrl(WebDriver driver) {
        return assertThat(driver.getCurrentUrl());
    }

    public AbstractStringAssert<?> assertThatUrlEventuallySatisfies(Consumer<AbstractStringAssert<?>> assertUrl) {
        await().atMost(AWAIT_AT_MOST_SECONDS)
                .untilAsserted(() -> assertUrl.accept(assertThatUrl(driver)));
        return assertThatUrl();
    }

    public AbstractStringAssert<?> assertThatUrl() {
        return assertThat(driver.getCurrentUrl());
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

    public static void validateUrlStartsWithWait(WebDriver driver, String currentUrlStart) throws InterruptedException {
        if (!driver.getCurrentUrl().startsWith(currentUrlStart)) {
            TimeUnit.SECONDS.sleep(5);
        }
        assertThat(driver.getCurrentUrl(), startsWith(currentUrlStart));
    }
}
