package org.cloudfoundry.identity.uaa.integration.pageObjects;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

public class Page {
    protected WebDriver driver;

    public Page(WebDriver driver) {
        this.driver = driver;
    }

    public LoginPage logout_goToLoginPage() {
        clickLogout();
        return new LoginPage(driver);
    }

    private void clickLogout() {
        driver.findElement(By.cssSelector(".dropdown-trigger")).click();
        driver.findElement(By.linkText("Sign Out")).click();
    }
}
