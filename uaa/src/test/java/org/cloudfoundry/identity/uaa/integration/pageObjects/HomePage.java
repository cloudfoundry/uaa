package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.cloudfoundry.identity.uaa.home.HomeController;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.springframework.ui.Model;

import java.security.Principal;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The HomePage class represents the home page on the UAA server.
 * It can have either url: `/home` or just `/`.
 * {@link HomeController#home(Model, Principal)}
 */
public class HomePage extends Page {
    private static final String SLASH_URL_PATH = "/";
    private static final String HOME_URL_PATH = "/home";

    public HomePage(WebDriver driver) {
        super(driver);
        Consumer<String> endsWithSlash = url -> assertThat(url).endsWith(SLASH_URL_PATH);
        Consumer<String> endsWithHome = url -> assertThat(url).endsWith(HOME_URL_PATH);
        assertThatUrlEventuallySatisfies(assertUrl -> assertUrl.satisfiesAnyOf(endsWithSlash, endsWithHome));
        assertThatPageSource().contains("Where to?");
    }

    public HomePage(WebDriver driver, String baseUrl) {
        this(driver);
        this.baseUrl = baseUrl;
    }

    public static LoginPage assertThatGoHome_redirectsToLoginPage(WebDriver driver, String baseUrl) {
        driver.get(baseUrl + SLASH_URL_PATH);
        return new LoginPage(driver, baseUrl);
    }

    public HomePage goHome() {
        driver.get(baseUrl + "/home");
        return this;
    }

    public boolean hasLastLoginTime() {
        WebElement lastLoginTime = driver.findElement(By.id("last_login_time"));
        String loginTime = lastLoginTime.getText();
        return loginTime != null && !loginTime.isBlank();
    }
}
