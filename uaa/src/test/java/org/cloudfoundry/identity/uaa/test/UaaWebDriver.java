package org.cloudfoundry.identity.uaa.test;

import java.time.Duration;
import java.util.List;
import java.util.Set;

import org.jspecify.annotations.Nullable;
import org.openqa.selenium.By;
import org.openqa.selenium.ElementNotInteractableException;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.StaleElementReferenceException;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.remote.RemoteWebDriver;
import org.openqa.selenium.remote.SessionId;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.FluentWait;
import org.openqa.selenium.support.ui.WebDriverWait;

/**
 * Thin wrapper around a "regular" webdriver, that allows you to "click-and-wait" until
 * an element has disappeared. This avoids explicit waits in test code.
 * <p>
 * Context: the {@link WebElement#click()} explicit states that it will _not_ wait for the
 * page reload to happen, and it should be the consuming code's responsibility.
 */
public class UaaWebDriver implements WebDriver {

    private final WebDriver delegate;

    public UaaWebDriver(WebDriver delegate) {
        this.delegate = delegate;
    }

    /**
     * Click on the element, and wait for a page reload. This is accomplished by waiting
     * for the reference to the clicked element to become "stale", ie not be in the current
     * DOM anymore, throwing {@link StaleElementReferenceException}. Sometimes, the Chrome driver
     * throws a 500 error, which body contains code -32000, so we use that as a signal as well.
     */
    public void clickAndWait(By locator) {
        var clickableElement = this.delegate.findElement(locator);
        clickableElement.click();

        new FluentWait<>(this.delegate).withTimeout(Duration.ofSeconds(5))
                .pollingEvery(Duration.ofMillis(100))
                .withMessage(() -> "Waiting for navigation after clicking on [%s]. Current URL [%s].".formatted(locator, delegate.getCurrentUrl()))
                .until((d) -> {
                    try {
                        clickableElement.isDisplayed();
                        return false;
                    } catch (StaleElementReferenceException e) {
                        return true;
                    } catch (WebDriverException e) {
                        return e.getMessage().contains("-32000");
                    }
                });
    }

    /**
     * Press the UAA navigation element with the given id, and wait for the button with a given id
     * Example: After Login to UAA there is a menu in the top right corner with. A user can click on it and get
     * the profile page or perform a logout.
     */
    public void pressUaaNavigation(String navigationElementId, String idButton) {
        WebDriverWait wait1 = new WebDriverWait(this.delegate, Duration.ofSeconds(10));
        WebElement elm1 = wait1.ignoreAll(List.of(StaleElementReferenceException.class, ElementNotInteractableException.class)).until(ExpectedConditions.visibilityOfElementLocated(By.id(navigationElementId)));
        elm1.click();
        WebDriverWait wait2 = new WebDriverWait(this.delegate, Duration.ofSeconds(30));
        WebElement elm2 = wait2.ignoreAll(List.of(StaleElementReferenceException.class, ElementNotInteractableException.class)).until(ExpectedConditions.visibilityOfElementLocated(By.id(idButton)));
        elm2.click();
    }

    public JavascriptExecutor getJavascriptExecutor() {
        return (JavascriptExecutor) this.delegate;
    }

    @Override
    public void get(String url) {
        this.delegate.get(url);
    }

    @Override
    public @Nullable String getCurrentUrl() {
        return this.delegate.getCurrentUrl();
    }

    @Override
    public @Nullable String getTitle() {
        return this.delegate.getTitle();
    }

    @Override
    public List<WebElement> findElements(By by) {
        return this.delegate.findElements(by);
    }

    @Override
    public WebElement findElement(By by) {
        return this.delegate.findElement(by);
    }

    @Override
    public @Nullable String getPageSource() {
        return this.delegate.getPageSource();
    }

    @Override
    public void close() {
        this.delegate.close();
    }

    @Override
    public void quit() {
        this.delegate.quit();
    }

    @Override
    public Set<String> getWindowHandles() {
        return this.delegate.getWindowHandles();
    }

    @Override
    public String getWindowHandle() {
        return this.delegate.getWindowHandle();
    }

    @Override
    public TargetLocator switchTo() {
        return this.delegate.switchTo();
    }

    @Override
    public Navigation navigate() {
        return this.delegate.navigate();
    }

    @Override
    public Options manage() {
        return this.delegate.manage();
    }

    public SessionId getSessionId() {
        return ((RemoteWebDriver) this.delegate).getSessionId();
    }

    public TakesScreenshot getTakesScreenShot() {
        return (TakesScreenshot) this.delegate;
    }
}
