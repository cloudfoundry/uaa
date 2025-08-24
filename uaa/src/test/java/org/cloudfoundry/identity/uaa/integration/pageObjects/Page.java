package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.assertj.core.api.AbstractStringAssert;
import org.cloudfoundry.identity.uaa.test.UaaWebDriver;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;

import java.time.Duration;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * The Page class is the base class, representing a web page.
 * It provides methods for validating the URL, page source, and title,
 * as well as performing common page actions like logging out and clearing cookies.
 */
public class Page {

    // This is the global setting that selenium waits during operations.
    // It should be small, as changing this value will increase the time tests take to run.
    protected static final Duration IMPLICIT_WAIT_SECONDS = Duration.ofSeconds(5);

    // This is used to control the max time that awaitility will check to see if
    // an assertion passes, before failing the test.
    protected static final Duration AWAIT_AT_MOST_SECONDS = Duration.ofSeconds(30);

    // This is the base URL of the UAA zone under test.
    protected String baseUrl;

    protected WebDriver driver;


    public Page(WebDriver driver) {
        this.driver = driver;
        driver.manage().timeouts().implicitlyWait(IMPLICIT_WAIT_SECONDS);
    }

    public Page(WebDriver driver, String baseUrl) {
        this(driver);
        this.baseUrl = baseUrl;
    }

    public static AbstractStringAssert<?> assertThatUrlEventuallySatisfies(WebDriver driver, Consumer<AbstractStringAssert<?>> assertUrl) {
        await().atMost(AWAIT_AT_MOST_SECONDS)
                .untilAsserted(() -> assertUrl.accept(assertThatUrl(driver)));
        return assertThatUrl(driver);
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

    public AbstractStringAssert<?> assertThatPageSource() {
        return assertThat(driver.getPageSource());
    }

    public AbstractStringAssert<?> assertThatTitle() {
        return assertThat(driver.getTitle());
    }

    public LoginPage assertThatLogout_goesToLoginPage(String baseUrl) {
        return clickLogout(baseUrl);
    }

    private LoginPage clickLogout(String baseUrl) {
        try {
            ((UaaWebDriver) driver).pressUaaNavigation("nav-dropdown-button", "nav-dropdown-content-logout");
        } catch (WebDriverException e) {
            driver.get(baseUrl + "/logout.do");
        }
        // check that we end in /login
        return LoginPage.go(driver, baseUrl).assertThatLoginPageShown();
    }

    public void clearCookies() {
        driver.manage().deleteAllCookies();
    }
}
