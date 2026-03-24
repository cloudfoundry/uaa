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

import org.cloudfoundry.identity.uaa.integration.pageObjects.LoginPage;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.integration.util.ScreenshotOnFailExtension;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.UaaWebDriver;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.web.client.RestTemplate;
import org.cloudfoundry.identity.uaa.extensions.EnabledIfZonePathsEnabled;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

/**
 * Integration test for zone-namespaced session when using path-based zones (/z/{subdomain}/).
 * This is the <b>required</b> integration test for zone session paths: it is the one place
 * that must cover separate sessions per zone, profile isolation, and per-zone logout.
 * <p>
 * Verifies that a single JSESSIONID can hold separate sessions per zone and that logging out
 * of one zone does not affect sessions in other zones.
 * <p>
 * Runs against the same integration server as all other {@code *IT} tests (no exclusions).
 * See docs/session-persistence-zone-paths.md for zone session behavior.
 */
@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
@ExtendWith(ScreenshotOnFailExtension.class)
@EnabledIfZonePathsEnabled
class ZoneSessionPathsIT {

    private static final String PASSWORD = "secr3T";
    private static final String ZONE1 = "testzone1";
    private static final String ZONE2 = "testzone2";
    private static final String DEFAULT_ZONE = "default";

    @Autowired
    @RegisterExtension
    private IntegrationTestExtension integrationTestExtension;

    @Autowired
    UaaWebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    private String userDefaultEmail;
    private String userZone1Email;
    private String userZone2Email;
    private RestTemplate identityClient;
    private RestTemplate adminClient;
    private String adminToken;

    @BeforeEach
    void setUp() {
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(zonePathUrl(ZONE1) + "/logout.do");
        webDriver.get(zonePathUrl(ZONE2) + "/logout.do");
        webDriver.manage().deleteAllCookies();

        adminToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");
        adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret"));
        identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl,
                        new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret"));

        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.getCorsPolicy().getDefaultConfiguration().setAllowedMethods(List.of(GET.toString(), POST.toString()));
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, ZONE1, ZONE1, config);
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, ZONE2, ZONE2, config);

        long suffix = System.currentTimeMillis();
        userDefaultEmail = "zonesession-default-" + suffix + "@example.com";
        userZone1Email = "zonesession-zone1-" + suffix + "@example.com";
        userZone2Email = "zonesession-zone2-" + suffix + "@example.com";

        IntegrationTestUtils.createUser(adminClient, baseUrl, userDefaultEmail, "Default", "User", userDefaultEmail, true);
        IntegrationTestUtils.createUser(adminToken, baseUrl, scimUser(userZone1Email, "Zone1", "User"), ZONE1);
        IntegrationTestUtils.createUser(adminToken, baseUrl, scimUser(userZone2Email, "Zone2", "User"), ZONE2);
    }

    private static ScimUser scimUser(String username, String givenName, String familyName) {
        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.setName(new ScimUser.Name(givenName, familyName));
        user.addEmail(username);
        user.setVerified(true);
        user.setActive(true);
        user.setPassword(PASSWORD);
        user.setVersion(0);
        return user;
    }

    @AfterEach
    void tearDown() {
        try {
            IntegrationTestUtils.deleteZone(baseUrl, ZONE1, adminToken);
        } catch (Exception ignored) {
        }
        try {
            IntegrationTestUtils.deleteZone(baseUrl, ZONE2, adminToken);
        } catch (Exception ignored) {
        }
    }

    @Test
    void loginToDefaultZoneAndVerifyProfile() {
        LoginPage.go(webDriver, baseUrl)
                .sendLoginCredentials(userDefaultEmail, PASSWORD);
        webDriver.get(baseUrl + "/profile");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Account Settings");
        assertThat(webDriver.getPageSource()).contains(userDefaultEmail);
    }

    @Test
    void loginToDefaultZoneAndBothPathZonesThenVerifyProfileInEach() {
        LoginPage.go(webDriver, baseUrl)
                .sendLoginCredentials(userDefaultEmail, PASSWORD);
        webDriver.get(baseUrl + "/profile");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Account Settings");
        assertThat(webDriver.getPageSource()).contains(userDefaultEmail);

        LoginPage.go(webDriver, zonePathUrl(ZONE1))
                .sendLoginCredentials(userZone1Email, PASSWORD);
        webDriver.get(zonePathUrl(ZONE1) + "/profile");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Account Settings");
        assertThat(webDriver.getPageSource()).contains(userZone1Email);

        LoginPage.go(webDriver, zonePathUrl(ZONE2))
                .sendLoginCredentials(userZone2Email, PASSWORD);
        webDriver.get(zonePathUrl(ZONE2) + "/profile");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Account Settings");
        assertThat(webDriver.getPageSource()).contains(userZone2Email);

        //lets move around too
        webDriver.get(baseUrl + "/profile");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Account Settings");
        assertThat(webDriver.getPageSource()).contains(userDefaultEmail);

        webDriver.get(zonePathUrl(ZONE1) + "/profile");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Account Settings");
        assertThat(webDriver.getPageSource()).contains(userZone1Email);

        webDriver.get(zonePathUrl(ZONE2) + "/profile");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Account Settings");
        assertThat(webDriver.getPageSource()).contains(userZone2Email);
    }

    /**
     * Verifies that the default zone path (/z/default/...) shares the same session as the base path.
     * Login at the base path (e.g. /uaa/login), then access profile via /z/default/profile — the same
     * user session must be visible because ZonePathContextRewritingFilter rewrites /z/default/ to the
     * original context path and does not set ZONE_SUBDOMAIN_FROM_PATH, so the session key is the same.
     */
    @Test
    void loginToDefaultZoneUsingBasePath() {
        LoginPage.go(webDriver, baseUrl)
                .sendLoginCredentials(userDefaultEmail, PASSWORD);
        webDriver.get(baseUrl + "/profile");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Account Settings");
        assertThat(webDriver.getPageSource()).contains(userDefaultEmail);

        webDriver.get(zonePathUrl(DEFAULT_ZONE) + "/profile");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Account Settings");
        assertThat(webDriver.getPageSource()).contains(userDefaultEmail);

        webDriver.get(baseUrl + "/logout.do");

        webDriver.get(zonePathUrl(DEFAULT_ZONE) + "/profile");
        assertThat(webDriver.getCurrentUrl())
                .as("After logging out of the default zone, visiting /z/default/ profile should redirect to /z/default/login login page")
                .contains("/uaa/z/" + DEFAULT_ZONE + "/login");


        webDriver.get(baseUrl + "/profile");
        assertThat(webDriver.getCurrentUrl())
                .as("After logging out of default zone, visiting default zone profile should redirect to default zone login page")
                .contains("/uaa/login");

    }

    /**
     * Verifies that logging in via the default zone path (/z/default/login) uses the same session as the base path.
     * Login at /uaa/z/default/login, then access profile via /z/default/profile and via base /uaa/profile — both
     * must show the same user because the filter rewrites /z/default/ so context path stays /uaa and the session
     * key is the same as for the base path. Browsing to base path after zone-path login must still show the user.
     */
    @Test
    void loginToDefaultZoneUsingZonePath() {
        LoginPage.go(webDriver, zonePathUrl(DEFAULT_ZONE))
                .sendLoginCredentials(userDefaultEmail, PASSWORD);
        webDriver.get(zonePathUrl(DEFAULT_ZONE) + "/profile");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Account Settings");
        assertThat(webDriver.getPageSource()).contains(userDefaultEmail);

        webDriver.get(baseUrl + "/profile");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Account Settings");
        assertThat(webDriver.getPageSource()).contains(userDefaultEmail);

        webDriver.get(zonePathUrl(DEFAULT_ZONE) + "/logout.do");

        webDriver.get(zonePathUrl(DEFAULT_ZONE) + "/profile");
        assertThat(webDriver.getCurrentUrl())
                .as("After logging out of the default zone, visiting /z/default/ profile should redirect to /z/default/login login page")
                .contains("/uaa/z/" + DEFAULT_ZONE + "/login");


        webDriver.get(baseUrl + "/profile");
        assertThat(webDriver.getCurrentUrl())
                .as("After logging out of default zone, visiting default zone profile should redirect to default zone login page")
                .contains("/uaa/login");


    }

    @Test
    void logoutOfOnePathZoneLeavesOtherZonesLoggedIn() {
        LoginPage.go(webDriver, baseUrl)
                .sendLoginCredentials(userDefaultEmail, PASSWORD);
        LoginPage.go(webDriver, zonePathUrl(ZONE1))
                .sendLoginCredentials(userZone1Email, PASSWORD);
        LoginPage.go(webDriver, zonePathUrl(ZONE2))
                .sendLoginCredentials(userZone2Email, PASSWORD);

        webDriver.get(zonePathUrl(ZONE1) + "/logout.do");

        webDriver.get(baseUrl + "/profile");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Account Settings");
        assertThat(webDriver.getPageSource()).contains(userDefaultEmail);

        webDriver.get(zonePathUrl(ZONE2) + "/profile");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Account Settings");
        assertThat(webDriver.getPageSource()).contains(userZone2Email);

        webDriver.get(zonePathUrl(ZONE1) + "/profile");
        assertThat(webDriver.getCurrentUrl())
                .as("After logging out of zone1, visiting zone1 profile should redirect to zone1 login page")
                .contains("/z/" + ZONE1 + "/login");
    }

    @Test
    void mainJSESSIONIDCookieDeletedAfterAllLogout() {
        LoginPage.go(webDriver, baseUrl)
                .sendLoginCredentials(userDefaultEmail, PASSWORD);
        webDriver.get(baseUrl + "/profile");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Account Settings");
        assertThat(webDriver.getPageSource()).contains(userDefaultEmail);

        LoginPage.go(webDriver, zonePathUrl(ZONE1))
                .sendLoginCredentials(userZone1Email, PASSWORD);
        webDriver.get(zonePathUrl(ZONE1) + "/profile");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Account Settings");
        assertThat(webDriver.getPageSource()).contains(userZone1Email);

        LoginPage.go(webDriver, zonePathUrl(ZONE2))
                .sendLoginCredentials(userZone2Email, PASSWORD);
        webDriver.get(zonePathUrl(ZONE2) + "/profile");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Account Settings");
        assertThat(webDriver.getPageSource()).contains(userZone2Email);

        //lets move around too
        webDriver.get(baseUrl + "/profile");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Account Settings");
        assertThat(webDriver.getPageSource()).contains(userDefaultEmail);

        webDriver.get(zonePathUrl(ZONE1) + "/profile");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Account Settings");
        assertThat(webDriver.getPageSource()).contains(userZone1Email);

        webDriver.get(zonePathUrl(ZONE2) + "/profile");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Account Settings");
        assertThat(webDriver.getPageSource()).contains(userZone2Email);

        //logout of all zones
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(zonePathUrl(ZONE1) + "/logout.do");
        webDriver.get(zonePathUrl(ZONE2) + "/logout.do");

        Set<Cookie> cookiesList = webDriver.manage().getCookies();
        System.out.println("Cookies: " + cookiesList);

        webDriver.get(zonePathUrl(ZONE1) + "/profile");
        assertThat(webDriver.getCurrentUrl())
                .as("After logging out of zone1, visiting zone1 profile should redirect to zone1 login page")
                .contains("/z/" + ZONE1 + "/login");

        webDriver.get(zonePathUrl(ZONE2) + "/profile");
        assertThat(webDriver.getCurrentUrl())
                .as("After logging out of zone2, visiting zone2 profile should redirect to zone2 login page")
                .contains("/z/" + ZONE2 + "/login");

        webDriver.get(baseUrl + "/profile");
        assertThat(webDriver.getCurrentUrl())
                .as("After logging out of default zone, visiting default zone profile should redirect to default zone login page")
                .contains("/uaa/login");
    }

    private String zonePathUrl(String subdomain) {
        return baseUrl + "/z/" + subdomain;
    }
}
