/*******************************************************************************
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
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.openqa.selenium.Dimension;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.logging.LogType;
import org.openqa.selenium.logging.LoggingPreferences;
import org.openqa.selenium.remote.CapabilityType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

@PropertySource("classpath:integration.test.properties")
public class DefaultIntegrationTestConfig {
    static final int IMPLICIT_WAIT_TIME = 15;
    static final int PAGE_LOAD_TIMEOUT = 20;
    static final int SCRIPT_TIMEOUT = 15;

    private final int timeoutMultiplier;

    public DefaultIntegrationTestConfig(@Value("${integration.test.timeout_multiplier}") int timeoutMultiplier) {
        this.timeoutMultiplier = timeoutMultiplier;
    }

    @Bean
    public IntegrationTestRule integrationTestRule(
            final @Value("${integration.test.base_url}") String baseUrl) {
        return new IntegrationTestRule(baseUrl);
    }

    @Bean
    public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
        return new PropertySourcesPlaceholderConfigurer();
    }

    @Bean(destroyMethod = "quit")
    public ChromeDriver webDriver() {
        System.setProperty("webdriver.chrome.logfile", "/tmp/chromedriver.log");
        System.setProperty("webdriver.chrome.verboseLogging", "true");

        ChromeOptions options = new ChromeOptions();
        options.addArguments(
          "--verbose",
          "--headless",
          "--disable-web-security",
          "--ignore-certificate-errors",
          "--allow-running-insecure-content",
          "--allow-insecure-localhost",
          "--no-sandbox",
          "--disable-gpu"
        );

        LoggingPreferences logs = new LoggingPreferences();
        logs.enable(LogType.PERFORMANCE, Level.ALL);
        options.setCapability(CapabilityType.LOGGING_PREFS, logs);
        options.setAcceptInsecureCerts(true);

        ChromeDriver driver = new ChromeDriver(options);

        driver.manage().timeouts()
                .implicitlyWait(IMPLICIT_WAIT_TIME * timeoutMultiplier, TimeUnit.SECONDS)
                .pageLoadTimeout(PAGE_LOAD_TIMEOUT * timeoutMultiplier, TimeUnit.SECONDS)
                .setScriptTimeout(SCRIPT_TIMEOUT * timeoutMultiplier, TimeUnit.SECONDS);
        driver.manage().window().setSize(new Dimension(1024, 768));
        return driver;
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
        protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
            super.prepareConnection(connection, httpMethod);
            connection.setInstanceFollowRedirects(false);
        }
    }
}
