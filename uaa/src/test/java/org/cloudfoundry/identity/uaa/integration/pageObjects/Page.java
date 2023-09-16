package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;

public class Page {
    protected WebDriver driver;

    public Page(WebDriver driver) {
        this.driver = driver;
    }

    public LoginPage begin(String baseUrl) {
        driver.get(baseUrl + "/login");
        return new LoginPage(driver);
    }

    public LoginPage logout() {
        clickLogout();
        return new LoginPage(driver);
    }

    private void clickLogout() {
        driver.findElement(By.cssSelector(".dropdown-trigger")).click();
        driver.findElement(By.linkText("Sign Out")).click();
    }
}
