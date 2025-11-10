/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.integration.feature;

import com.dumbster.smtp.SimpleSmtpServer;
import org.cloudfoundry.identity.uaa.oauth.client.test.TestAccounts;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.test.UaaWebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.time.Duration;

@PropertySource("classpath:integration.test.properties")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD, hierarchyMode = DirtiesContext.HierarchyMode.EXHAUSTIVE)
public class DefaultIntegrationTestConfig {
    static final Duration IMPLICIT_WAIT_TIME = Duration.ofSeconds(30L);
    static final Duration PAGE_LOAD_TIMEOUT = Duration.ofSeconds(40L);
    static final Duration SCRIPT_TIMEOUT = Duration.ofSeconds(30L);

    private final int timeoutMultiplier;

    public DefaultIntegrationTestConfig(@Value("${integration.test.timeout_multiplier}") int timeoutMultiplier) {
        this.timeoutMultiplier = timeoutMultiplier;
    }

    @Bean
    public IntegrationTestExtension integrationTestExtension(
            final @Value("${integration.test.base_url}") String baseUrl) {
        return new IntegrationTestExtension(baseUrl);
    }

    @Bean
    public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
        return new PropertySourcesPlaceholderConfigurer();
    }

    @Bean(destroyMethod = "quit")
    public UaaWebDriver webDriver() {
        System.setProperty("webdriver.chrome.logfile", "/tmp/chromedriver.log");
        System.setProperty("webdriver.chrome.verboseLogging", "true");
        System.setProperty("webdriver.http.factory", "jdk-http-client");

        ChromeDriver driver = new ChromeDriver(getChromeOptions());
        driver.manage().timeouts()
                .implicitlyWait(IMPLICIT_WAIT_TIME.multipliedBy(timeoutMultiplier))
                .pageLoadTimeout(PAGE_LOAD_TIMEOUT.multipliedBy(timeoutMultiplier))
                .scriptTimeout(SCRIPT_TIMEOUT.multipliedBy(timeoutMultiplier));
        return new UaaWebDriver(driver);
    }

    private static ChromeOptions getChromeOptions() {
        ChromeOptions options = new ChromeOptions();
        options.addArguments(
                // Comment the following line to run selenium test browser in Headed Mode
                "--headless=new", // Use new headless mode (more stable)
                "--guest", //attempt to disable password checkups that disrupt the flow
                "--disable-web-security",
                "--ignore-certificate-errors",
                "--allow-running-insecure-content",
                "--allow-insecure-localhost",
                "--no-sandbox", // Required for Docker/CI environments
                "--disable-gpu",
                "--remote-allow-origins=*",
                "--disable-dev-shm-usage", // Overcome limited resource problems in Docker
                // Additional stability flags
                "--disable-extensions",
                "--disable-software-rasterizer",
                "--disable-background-timer-throttling",
                "--disable-backgrounding-occluded-windows",
                "--disable-renderer-backgrounding",
                "--disable-blink-features=AutomationControlled",
                "--disable-features=TranslateUI",
                // Hang detection and renderer stability flags
                "--disable-hang-monitor", // Prevents Chrome from killing "hung" renderer processes (useful for slow backend responses)
                "--disable-background-networking", // Reduces background network activity that could interfere with test requests
                "--disable-features=RendererScheduling", // Disables aggressive renderer scheduling that might cause timeouts
                "--run-all-compositor-stages-before-draw", // Ensures all rendering stages complete before drawing (prevents partial renders)
                "--disable-prompt-on-repost",
                "--disable-sync",
                "--disable-component-extensions-with-background-pages",
                "--force-color-profile=srgb",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-default-apps",
                "--disable-popup-blocking",
                "--test-type",
                "--disable-infobars"
        );
        options.setAcceptInsecureCerts(true);
        
        // Set page load strategy to 'normal' to ensure proper page load detection
        options.setPageLoadStrategy(org.openqa.selenium.PageLoadStrategy.NORMAL);

        return options;
    }

    @Bean(destroyMethod = "stop")
    public SimpleSmtpServer simpleSmtpServer(@Value("${smtp.port}") int port) {
        return SimpleSmtpServer.start(port);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @Bean
    public TestClient testClient(RestTemplate restTemplate,
                                 final @Value("${integration.test.base_url}") String baseUrl) {
        return new TestClient(restTemplate, baseUrl);
    }

    @Bean
    public TestAccounts testAccounts() {
        return UaaTestAccounts.standard(null);
    }

    public static class HttpClientFactory extends SimpleClientHttpRequestFactory {
        @Override
        protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
            super.prepareConnection(connection, httpMethod);
            connection.setInstanceFollowRedirects(false);
        }
    }

    @Bean
    public SamlServerConfig samlServerConfig(@Value("${integration.test.saml.url}") String serverUrl) {
        return new SamlServerConfig(serverUrl);
    }

}
