package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

/**
 * The SamlLoginPage class represents the login page on the SimpleSAML server.
 * This class provides methods to interact with the SAML login page and perform login actions.
 * It has url matching: `/module.php/core/loginuserpass`.
 */
public class SamlLoginPage extends Page {
    // This is on the saml server, not the UAA server
    private static final String URL_PATH = "/module.php/core/loginuserpass";

    public SamlLoginPage(WebDriver driver) {
        super(driver);
        assertThatUrlEventuallySatisfies(assertUrl -> assertUrl.contains(URL_PATH));
    }

    public HomePage assertThatLogin_goesToHomePage(String username, String password) {
        sendLoginCredentials(username, password);
        return new HomePage(driver);
    }

    public PasscodePage assertThatLogin_goesToPasscodePage(String username, String password) {
        sendLoginCredentials(username, password);
        return new PasscodePage(driver);
    }

    public CustomErrorPage assertThatLogin_goesToCustomErrorPage(String username, String password, String urlContent) {
        sendLoginCredentials(username, password);
        return new CustomErrorPage(driver, urlContent);
    }

    public SamlErrorPage assertThatLogin_goesToSamlErrorPage(String username, String password) {
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
