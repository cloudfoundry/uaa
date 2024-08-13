package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.hamcrest.Matcher;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import static org.hamcrest.Matchers.containsString;

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
        validateUrl(driver, containsString(URL_PATH));
    }

    public HomePage login_goesToHomePage(String username, String password) {
        sendLoginCredentials(username, password);
        return new HomePage(driver);
    }

    public PasscodePage login_goesToPasscodePage(String username, String password) {
        sendLoginCredentials(username, password);
        return new PasscodePage(driver);
    }

    public CustomErrorPage login_goesToCustomErrorPage(String username, String password, Matcher<String>  urlMatcher) {
        sendLoginCredentials(username, password);
        return new CustomErrorPage(driver, urlMatcher);
    }

    public SamlErrorPage login_goesToSamlErrorPage(String username, String password) {
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
