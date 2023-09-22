package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThat;

public class SamlLoginPage extends Page {
    public SamlLoginPage(WebDriver driver) {
        super(driver);
        assertThat("Should be on the SAML login page", driver.getCurrentUrl(), containsString("/module.php/core/loginuserpass"));
    }

    public HomePage login_goToHomePage(String username, String password) {
        sendLoginCredentials(username, password);
        return new HomePage(driver);
    }

    public PasscodePage login_goToPasscodePage(String username, String password) {
        sendLoginCredentials(username, password);
        return new PasscodePage(driver);
    }

    private void sendLoginCredentials(String username, String password) {
        final WebElement usernameElement = driver.findElement(By.name("username"));
        usernameElement.clear();
        usernameElement.sendKeys(username);
        driver.findElement(By.name("password")).sendKeys(password);
        driver.findElement(By.id("submit_button")).click();
    }
}