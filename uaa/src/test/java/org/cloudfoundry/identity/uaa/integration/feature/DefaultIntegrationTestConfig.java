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
import org.openqa.selenium.Dimension;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.time.Duration;

@PropertySource("classpath:integration.test.properties")
public class DefaultIntegrationTestConfig {
    static final Duration IMPLICIT_WAIT_TIME = Duration.ofSeconds(30L);
    static final Duration PAGE_LOAD_TIMEOUT = Duration.ofSeconds(40L);
    static final Duration SCRIPT_TIMEOUT = Duration.ofSeconds(30L);

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
        System.setProperty("webdriver.http.factory", "jdk-http-client");

        ChromeDriver driver = new ChromeDriver(getChromeOptions());
        driver.manage().timeouts()
                .implicitlyWait(IMPLICIT_WAIT_TIME.multipliedBy(timeoutMultiplier))
                .pageLoadTimeout(PAGE_LOAD_TIMEOUT.multipliedBy(timeoutMultiplier))
                .scriptTimeout(SCRIPT_TIMEOUT.multipliedBy(timeoutMultiplier));
        driver.manage().window().setSize(new Dimension(1024, 768));
        return driver;
    }

    private static ChromeOptions getChromeOptions() {
        ChromeOptions options = new ChromeOptions();
        options.addArguments(
                "--verbose",
                // Comment the following line to run selenium test browser in Headed Mode
                "--headless=old",
                "--window-position=-2400,-2400",
                "--window-size=1024,768",
                "--disable-web-security",
                "--ignore-certificate-errors",
                "--allow-running-insecure-content",
                "--allow-insecure-localhost",
                "--no-sandbox",
                "--disable-gpu",
                "--remote-allow-origins=*"
        );
        options.setAcceptInsecureCerts(true);

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
}
