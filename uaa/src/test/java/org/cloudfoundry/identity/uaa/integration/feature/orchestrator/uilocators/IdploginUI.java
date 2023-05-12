package org.cloudfoundry.identity.uaa.integration.feature.orchestrator.uilocators;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

public class IdploginUI {
    WebDriver driver;

    public IdploginUI(WebDriver driver) {
        this.driver = driver;
    }

    By IDPUserName = By.xpath("//input[@name='username']");
    By IDPPassword = By.xpath("//input[@name='password']");
    By clickOnSignIn = By.xpath("//input[@value='Sign in']");
    By welcomecheck = By.xpath("//h1[contains(text(), 'Welcome to testzone1!')]");

    public void enterIDPuserName(String EnterIDPuserName) {
        driver.findElement(IDPUserName).sendKeys(EnterIDPuserName);
    }

    public void enterIDPPassword(String enterIDPPassword) {
        driver.findElement(IDPPassword).sendKeys(enterIDPPassword);
    }

    public void clickOnSignIn() {
        driver.findElement(clickOnSignIn).click();
    }


    public void headLineCheck() {
        driver.findElement(welcomecheck).click();
    }
}


