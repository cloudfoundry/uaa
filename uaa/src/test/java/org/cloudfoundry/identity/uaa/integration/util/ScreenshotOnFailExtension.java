package org.cloudfoundry.identity.uaa.integration.util;

import org.apache.commons.io.FileUtils;
import org.cloudfoundry.identity.uaa.test.UaaWebDriver;
import org.junit.jupiter.api.extension.AfterTestExecutionCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.remote.RemoteWebDriver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class ScreenshotOnFailExtension implements AfterTestExecutionCallback {
    private static final Logger log = LoggerFactory.getLogger(ScreenshotOnFailExtension.class);

    @Override
    public void afterTestExecution(ExtensionContext context) {
        if (context.getExecutionException().isEmpty()) {
            // No exception, test passed
            return;
        }

        UaaWebDriver driver = SpringExtension.getApplicationContext(context).getBean(UaaWebDriver.class);
        if (hasWebDriverQuit(driver)) {
            // WebDriver has already quit
            log.debug("ScreenshotOnFail Requested, but webdriver has quit.");
            return;
        }

        String className = context.getRequiredTestClass().getName();
        String description = context.getDisplayName();

        File sourceScreenshotFile = driver.getTakesScreenShot().getScreenshotAs(OutputType.FILE);
        File screenshotFile = getDestinationFile(className, description, "png");
        try {
            FileUtils.copyFile(sourceScreenshotFile, screenshotFile);
        } catch (IOException ioe) {
            log.error("ScreenshotOnFail could not write image: {}", screenshotFile);
            return;
        }
        log.info("ScreenshotOnFail created image: {}", screenshotFile);

        String pageSource = driver.getPageSource();
        File pageSourceFile = getDestinationFile(className, description, "html");

        try {
            FileUtils.write(pageSourceFile, pageSource, StandardCharsets.UTF_8);
        } catch (IOException e) {
            log.error("ScreenshotOnFail could not write source: {}", pageSourceFile);
            return;
        }
        log.info("ScreenshotOnFail created source: {}", pageSourceFile);
    }

    private boolean hasWebDriverQuit(UaaWebDriver driver) {
        if (driver == null) {
            return true;
        }
        return driver.getSessionId() == null;
    }

    private File getDestinationFile(String className, String description, String extension) {
        String home = System.getProperty("user.home");
        String absoluteFileName = "%s/build/cloudfoundry/uaa/uaa/build/reports/tests/%s/%s.%s".formatted(home, className, description, extension);
        return new File(absoluteFileName);
    }
}
