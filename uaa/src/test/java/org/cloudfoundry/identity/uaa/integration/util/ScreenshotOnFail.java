package org.cloudfoundry.identity.uaa.integration.util;

import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FileUtils;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.WebDriver;

public class ScreenshotOnFail extends TestWatcher {
    private WebDriver browser;

    @Override
    protected void failed(Throwable e, Description description) {
        TakesScreenshot takesScreenshot = (TakesScreenshot) browser;

        File scrFile = takesScreenshot.getScreenshotAs(OutputType.FILE);
        File destFile = getDestinationFile(description);
        try {
            FileUtils.copyFile(scrFile, destFile);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    private File getDestinationFile(Description description) {
        String fileName = description.getClassName() + "/" + description.getMethodName() + ".png";
        String home = System.getProperty("user.home");
        String absoluteFileName = home + "/build/cloudfoundry/uaa/uaa/build/reports/tests/" + fileName;
        return new File(absoluteFileName);
    }

    public void setWebDriver(WebDriver webDriver) {
        this.browser = webDriver;
    }
}
