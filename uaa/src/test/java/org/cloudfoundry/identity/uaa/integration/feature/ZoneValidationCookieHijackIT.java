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

import org.cloudfoundry.identity.uaa.ServerRunningExtension;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.endpoints.LogoutDoEndpoint;
import org.cloudfoundry.identity.uaa.integration.endpoints.SamlLogoutAuthSourceEndpoint;
import org.cloudfoundry.identity.uaa.integration.pageObjects.LoginPage;
import org.cloudfoundry.identity.uaa.integration.pageObjects.Page;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.createSimplePHPSamlIDP;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.doesSupportZoneDNS;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

/**
 * Ensure zone is validated on AuthenticationToken
 *
 * @see SamlLoginIT
 */
@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
class ZoneValidationCookieHijackIT {
    private static final String SAML_ORIGIN = "simplesamlphp";
    private static final String LINK_TEXT_1 = "SAML provider 1";
    private static final String LINK_TEXT_2 = "SAML provider 2";

    @Autowired
    @RegisterExtension
    private IntegrationTestExtension integrationTestExtension;

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Autowired
    SamlServerConfig samlServerConfig;

    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    @BeforeAll
    static void checkZoneDNSSupport() {
        assertThat(doesSupportZoneDNS())
                .as("Expected testzone1.localhost, testzone2.localhost, testzone3.localhost, testzone4.localhost to resolve to 127.0.0.1")
                .isTrue();
    }

    @BeforeEach
    void clearWebDriverOfCookies() {
        for (String domain : Arrays.asList("localhost", "testzone1.localhost", "testzone2.localhost", "testzone3.localhost", "testzone4.localhost")) {
            LogoutDoEndpoint.logout(webDriver, baseUrl.replace("localhost", domain));
            new Page(webDriver).clearCookies();
        }
        SamlLogoutAuthSourceEndpoint.assertThatLogoutAuthSource_goesToSamlWelcomePage(webDriver, samlServerConfig);
    }

    @BeforeEach
    void setupZones() {
        String token = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");
        IntegrationTestUtils.ensureGroupExists(token, null, baseUrl, "zones.uaa.admin");
        IntegrationTestUtils.ensureGroupExists(token, null, baseUrl, "zones.testzone1.admin");
        IntegrationTestUtils.ensureGroupExists(token, null, baseUrl, "zones.testzone2.admin");
        IntegrationTestUtils.ensureGroupExists(token, null, baseUrl, "zones.testzone3.admin");
        IntegrationTestUtils.ensureGroupExists(token, null, baseUrl, "zones.testzone4.admin");
    }

    @AfterEach
    void afterEach() {
        String token = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");
        for (String zoneId : Arrays.asList("testzone1", "testzone2", "testzone3", "testzone4", "uaa")) {
            ScimGroup group = IntegrationTestUtils.getGroup(token, "", baseUrl, "zones.%s.admin".formatted(zoneId));
            if (group != null) {
                IntegrationTestUtils.deleteGroup(token, "", baseUrl, group.getId());
            }

            try {
                IntegrationTestUtils.deleteZone(baseUrl, zoneId, token);
                IntegrationTestUtils.deleteProvider(token, baseUrl, "uaa", zoneId + ".cloudfoundry-saml-login");
            } catch (Exception ignored) {
                // ignored
            }
        }
        IntegrationTestUtils.deleteProvider(token, baseUrl, "uaa", SAML_ORIGIN);
        IntegrationTestUtils.deleteProvider(token, baseUrl, "uaa", "simplesamlphp2");
    }

    protected IdentityProvider<SamlIdentityProviderDefinition> createIdentityProvider(String originKey) throws Exception {
        return IntegrationTestUtils.createIdentityProvider(originKey, true, baseUrl, serverRunning, samlServerConfig.getSamlServerUrl());
    }

    @Test
    void sessionCookieFromZone1DoesNotAllowZone2() {
        String zone1Id = "testzone1";
        String zone2Id = "testzone2";

        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );

        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.getCorsPolicy().getDefaultConfiguration().setAllowedMethods(List.of(GET.toString(), POST.toString()));
        IdentityZone zone1 = IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zone1Id, zone1Id, config);
        IdentityZone zone2 = IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zone2Id, zone2Id, config);
        String email = new RandomValueStringGenerator().generate() + "@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl, email, "firstname", "lastname", email, true);
        String group1Id = IntegrationTestUtils.findGroupId(adminClient, baseUrl, "zones." + zone1Id + ".admin");
        String group2Id = IntegrationTestUtils.findGroupId(adminClient, baseUrl, "zones." + zone2Id + ".admin");
        IntegrationTestUtils.addMemberToGroup(adminClient, baseUrl, user.getId(), group1Id);
        IntegrationTestUtils.addMemberToGroup(adminClient, baseUrl, user.getId(), group2Id);

        String zoneAdminToken =
                IntegrationTestUtils.getAccessTokenByAuthCode(serverRunning,
                        UaaTestAccounts.standard(serverRunning),
                        "identity",
                        "identitysecret",
                        email,
                        "secr3T");

        //we have to create two providers to avoid automatic redirect
        SamlIdentityProviderDefinition samlIdentityProviderDefinition1 = createTestZone1IDP(SAML_ORIGIN);
        samlIdentityProviderDefinition1.setIdpEntityAlias(samlIdentityProviderDefinition1.getIdpEntityAlias() + "-1");
        samlIdentityProviderDefinition1.setLinkText(LINK_TEXT_1);
        IdentityProvider<SamlIdentityProviderDefinition> provider1 = new IdentityProvider<>();
        provider1.setIdentityZoneId(zone1Id);
        provider1.setType(OriginKeys.SAML);
        provider1.setActive(true);
        provider1.setConfig(samlIdentityProviderDefinition1);
        provider1.setOriginKey(samlIdentityProviderDefinition1.getIdpEntityAlias());
        provider1.setName("simplesamlphp for testzone 1");
        provider1 = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider1);
        assertThat(provider1.getId()).isNotNull();

        //we have to create two providers to avoid automatic redirect
        SamlIdentityProviderDefinition samlIdentityProviderDefinition2 = createTestZone2IDP(SAML_ORIGIN);
        samlIdentityProviderDefinition2.setIdpEntityAlias(samlIdentityProviderDefinition2.getIdpEntityAlias() + "-2");
        samlIdentityProviderDefinition2.setLinkText(LINK_TEXT_2);
        IdentityProvider<SamlIdentityProviderDefinition> provider2 = new IdentityProvider<>();
        provider2.setIdentityZoneId(zone2Id);
        provider2.setType(OriginKeys.SAML);
        provider2.setActive(true);
        provider2.setConfig(samlIdentityProviderDefinition2);
        provider2.setOriginKey(samlIdentityProviderDefinition2.getIdpEntityAlias());
        provider2.setName("simplesamlphp for testzone 2");
        provider2 = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider2);
        assertThat(provider2.getId()).isNotNull();

        String testZone1Url = baseUrl.replace("localhost", zone1Id + ".localhost");
        String testZone2Url = baseUrl.replace("localhost", zone2Id + ".localhost");
        webDriver.get("%s/logout.do".formatted(baseUrl));
        webDriver.get("%s/logout.do".formatted(testZone1Url));
        webDriver.get("%s/logout.do".formatted(testZone2Url));

        // Login on zone 1
        webDriver.get("%s/login".formatted(testZone1Url));
        assertThat(webDriver.getTitle()).isEqualTo(zone1.getName());
        LoginPage loginPage1 = new LoginPage(webDriver);
        loginPage1.assertThatSamlLink_goesToSamlLoginPage(LINK_TEXT_1)
                .assertThatLogin_goesToHomePage("marissa", "koala");

        // capture the cookie from zone 1
        Cookie cookie = new Cookie("JSESSIONID", webDriver.manage().getCookieNamed("JSESSIONID").getValue(), "/uaa");
        webDriver.get("%s/login".formatted(testZone2Url));
        assertThat(webDriver.getTitle()).isEqualTo(zone2.getName());
        LoginPage loginPage2 = new LoginPage(webDriver);
        loginPage2.assertThatPageSource().doesNotContain("Where to?");

        // set the cookie from zone 1 and use on zone 2
        webDriver.manage().addCookie(cookie);
        webDriver.get("%s/login".formatted(testZone2Url));
        // should prompt for login again, not home page
        loginPage2 = new LoginPage(webDriver);
        loginPage2.assertThatPageSource().doesNotContain("Where to?");
    }

    public SamlIdentityProviderDefinition createTestZone1IDP(String alias) {
        return createSimplePHPSamlIDP(alias, "testzone1", samlServerConfig.getSamlServerUrl());
    }

    public SamlIdentityProviderDefinition createTestZone2IDP(String alias) {
        return createSimplePHPSamlIDP(alias, "testzone2", samlServerConfig.getSamlServerUrl());
    }
}