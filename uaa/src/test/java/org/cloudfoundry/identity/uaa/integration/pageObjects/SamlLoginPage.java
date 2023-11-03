package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import static org.hamcrest.Matchers.containsString;

public class SamlLoginPage extends Page {
    // This is on the saml server, not the UAA server
    static final protected String urlPath = "/module.php/core/loginuserpass";

    public SamlLoginPage(WebDriver driver) {
        super(driver);
        validateUrl(driver, containsString(urlPath));
    }

    public HomePage login_goToHomePage(String username, String password) {
        sendLoginCredentials(username, password);
        return new HomePage(driver);
    }

    public PasscodePage login_goToPasscodePage(String username, String password) {
        sendLoginCredentials(username, password);
        return new PasscodePage(driver);
    }

    public SamlErrorPage login_goToSamlErrorPage(String username, String password) {
        sendLoginCredentials(username, password);
        return new SamlErrorPage(driver);
    }

    private void sendLoginCredentials(String username, String password) {
        final WebElement usernameElement = driver.findElement(By.name("username"));
        usernameElement.clear();
        usernameElement.sendKeys(username);
        driver.findElement(By.name("password")).sendKeys(password);
        driver.findElement(By.id("submit_button")).click();
    }
}