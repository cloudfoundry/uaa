package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.cloudfoundry.identity.uaa.home.HomeController;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.springframework.ui.Model;

import java.security.Principal;

import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;

/**
 * The HomePage class represents the home page on the UAA server.
 * It can have either url: `/home` or just `/`.
 * {@link HomeController#home(Model, Principal)}
 */
public class HomePage extends Page {
    static final private String slashUrlPath = "/";
    static final private String homeUrlPath = "/home";

    public HomePage(WebDriver driver) {
        super(driver);
        validateUrl(driver, anyOf(endsWith(slashUrlPath), endsWith(homeUrlPath)));
        validatePageSource(driver, containsString("Where to?"));
    }

    static public LoginPage tryToGoHome_redirectsToLoginPage(WebDriver driver, String baseUrl) {
        driver.get(baseUrl + slashUrlPath);
        return new LoginPage(driver);
    }

    public boolean hasLastLoginTime() {
        WebElement lastLoginTime = driver.findElement(By.id("last_login_time"));
        String loginTime = lastLoginTime.getText();
        return loginTime != null && !loginTime.isBlank();
    }
}
