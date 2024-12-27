package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.assertj.core.api.AbstractStringAssert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

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
    protected WebDriver driver;

    public Page(WebDriver driver) {
        this.driver = driver;
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(5));
    }

    public static AbstractStringAssert<?> assertThatUrlEventuallySatisfies(WebDriver driver, Consumer<AbstractStringAssert<?>> assertUrl) {
        await().atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> assertUrl.accept(assertThatUrl(driver)));
        return assertThatUrl(driver);
    }

    private static AbstractStringAssert<?> assertThatUrl(WebDriver driver) {
        return assertThat(driver.getCurrentUrl());
    }

    public AbstractStringAssert<?> assertThatUrlEventuallySatisfies(Consumer<AbstractStringAssert<?>> assertUrl) {
        await().atMost(Duration.ofSeconds(5))
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

    public LoginPage assertThatLogout_goesToLoginPage() {
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
