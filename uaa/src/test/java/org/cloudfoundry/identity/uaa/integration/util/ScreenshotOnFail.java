package org.cloudfoundry.identity.uaa.integration.util;

import org.apache.commons.io.FileUtils;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.WebDriver;

import java.io.File;
import java.io.IOException;

public class ScreenshotOnFail extends TestWatcher {
    private WebDriver browser;

    @Override
    protected void failed(Throwable e, Description description) {
        debugPage(description.getClassName(), description.getMethodName() + ".png");
    }

    public void debugPage(String className, String description) {
        TakesScreenshot takesScreenshot = (TakesScreenshot) browser;

        File scrFile = takesScreenshot.getScreenshotAs(OutputType.FILE);
        File destFile = getDestinationFile(className, description);
        try {
            FileUtils.copyFile(scrFile, destFile);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }

        File pageSourceFile = getDestinationFile(className, description + ".html");
        String pageSource = browser.getPageSource();

        try {
            FileUtils.write(pageSourceFile, pageSource);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private File getDestinationFile(String className, String description) {
        String fileName = className + "/" + description;
        String home = System.getProperty("user.home");
        String absoluteFileName = home + "/build/cloudfoundry/uaa/uaa/build/reports/tests/" + fileName;
        return new File(absoluteFileName);
    }

    public void setWebDriver(WebDriver webDriver) {
        this.browser = webDriver;
    }
}
