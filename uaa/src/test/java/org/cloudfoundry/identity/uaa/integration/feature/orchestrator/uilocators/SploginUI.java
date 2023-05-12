package org.cloudfoundry.identity.uaa.integration.feature.orchestrator.uilocators;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

public class SploginUI {
    WebDriver driver;

    public SploginUI(WebDriver driver) {
        this.driver = driver;
    }

    By Gesso = By.xpath("//a[@class='saml-login-link']");


    public void clickOnSignInByGesso() {
        driver.findElement(Gesso).click();
    }


}
