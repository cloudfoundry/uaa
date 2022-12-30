package org.cloudfoundry.identity.uaa.integration.util;

import org.apache.commons.io.FileUtils;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.WebDriver;
import org.springframework.core.Ordered;
import org.springframework.test.context.TestContext;
import org.springframework.test.context.support.AbstractTestExecutionListener;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;

public class ScreenshotOnFail extends AbstractTestExecutionListener {
    private WebDriver browser;

    @Override
    public int getOrder() {
        // Position ScreenshotOnFailTestExecutionListener so that it's afterTestMethod() executes before
        // afterTestMethod() in spring-boot WebDriverTestExecutionListener and take the screenshot before
        // WebBrowser is closed
        return Ordered.LOWEST_PRECEDENCE - 99;
    }

    @Override
    public void afterTestMethod(TestContext testContext) throws Exception {
        if (testContext.getTestException() == null) {
            return;
        }

        Object test = testContext.getTestInstance();
        Field field = test.getClass().getDeclaredField("webDriver");
        field.setAccessible(true);
        this.browser = (WebDriver) field.get(test);

        debugPage(testContext.getTestClass().getName(), testContext.getTestMethod().getName() + ".png");
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
}
