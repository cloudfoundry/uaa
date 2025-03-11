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

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.ServerRunningExtension;
import org.cloudfoundry.identity.uaa.account.UserInfoResponse;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.endpoints.LogoutDoEndpoint;
import org.cloudfoundry.identity.uaa.integration.endpoints.SamlLogoutAuthSourceEndpoint;
import org.cloudfoundry.identity.uaa.integration.pageObjects.Page;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.integration.util.ScreenshotOnFailExtension;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.test.UaaWebDriver;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.web.client.RestTemplate;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.createSimplePHPSamlIDP;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.doesSupportZoneDNS;
import static org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken.ACCESS_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ATTRIBUTES;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_ATTRIBUTE_PREFIX;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

/**
 * NOTE: This Test Case was split from SamlLoginIT, since it was polluting some state
 * and causing later tests within SamlLoginIT to fail.
 * If we can determine the reason for the pollution, then this can be returned to SamlLoginIT.
 */
@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
@ExtendWith(ScreenshotOnFailExtension.class)
class SamlLoginCustomUserAttributesIT {

    private static final String SAML_ORIGIN = "simplesamlphp";
    private static final By byUsername = By.name("username");
    private static final By byPassword = By.name("password");

    @Autowired
    @RegisterExtension
    private IntegrationTestExtension integrationTestExtension;

    @Autowired
    UaaWebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    @Autowired
    SamlServerConfig samlServerConfig;

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

    protected IdentityProvider<SamlIdentityProviderDefinition> createIdentityProvider(String originKey) {
        return IntegrationTestUtils.createIdentityProvider(originKey, true, baseUrl, serverRunning, samlServerConfig.getSamlServerUrl());
    }

    @Test
    void samlLoginCustomUserAttributesAndRolesInIDToken() throws Exception {

        final String costCenter = "costCenter";
        final String costCenters = "costCenters";
        final String denverCo = "Denver,CO";
        final String manager = "manager";
        final String managers = "managers";
        final String johnTheSloth = "John the Sloth";
        final String kariTheAntEater = "Kari the Ant Eater";

        //ensure we are able to resolve DNS for hostname testzone1.localhost
        String zoneId = "testzone1";
        String zoneUrl = baseUrl.replace("localhost", "testzone1.localhost");

        //identity client token
        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );

        //admin client token - to create users
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );

        //create the zone
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.getCorsPolicy().getDefaultConfiguration().setAllowedMethods(List.of(GET.toString(), POST.toString()));
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId, config);

        //create a zone admin user
        String email = new RandomValueStringGenerator().generate() + "@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl, email, "firstname", "lastname", email, true);
        String groupId = IntegrationTestUtils.findGroupId(adminClient, baseUrl, "zones." + zoneId + ".admin");
        IntegrationTestUtils.addMemberToGroup(adminClient, baseUrl, user.getId(), groupId);

        //get the zone admin token
        String zoneAdminToken =
                IntegrationTestUtils.getAccessTokenByAuthCode(serverRunning,
                        UaaTestAccounts.standard(serverRunning),
                        "identity",
                        "identitysecret",
                        email,
                        "secr3T");

        // create a SAML external IDP
        SamlIdentityProviderDefinition samlIdentityProviderDefinition = createTestZone1IDP(SAML_ORIGIN);
        samlIdentityProviderDefinition.setStoreCustomAttributes(true);
        samlIdentityProviderDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX + costCenters, costCenter);
        samlIdentityProviderDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX + managers, manager);

        // External groups will only appear as roles if they are allowlisted
        samlIdentityProviderDefinition.setExternalGroupsWhitelist(List.of("*"));

        // External groups will only be found when there is a configured attribute name for them
        samlIdentityProviderDefinition.addAttributeMapping("external_groups", Collections.singletonList("groups"));

        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setIdentityZoneId(zoneId);
        provider.setType(OriginKeys.SAML);
        provider.setActive(true);
        provider.setConfig(samlIdentityProviderDefinition);
        provider.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        provider.setName("simplesamlphp for testzone1");

        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertThat(provider.getConfig().getIdpEntityAlias()).isEqualTo(provider.getOriginKey());
        List<String> idps = List.of(provider.getOriginKey());

        // set up a test client
        String adminClientInZone = new RandomValueStringGenerator().generate();
        UaaClientDetails clientDetails = new UaaClientDetails(adminClientInZone, null, "openid,user_attributes,roles", "authorization_code,client_credentials", "uaa.admin,scim.read,scim.write,uaa.resource", zoneUrl);
        clientDetails.setClientSecret("secret");
        clientDetails.setAutoApproveScopes(Collections.singleton("true"));
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);

        clientDetails = IntegrationTestUtils.createClientAsZoneAdmin(zoneAdminToken, baseUrl, zoneId, clientDetails);
        clientDetails.setClientSecret("secret");

        IntegrationTestUtils.getClientCredentialsToken(zoneUrl, clientDetails.getClientId(), "secret");
        webDriver.get("%s/logout.do".formatted(zoneUrl));

        String authUrl = "%s/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&state=8tp0tR"
                .formatted(zoneUrl, clientDetails.getClientId(), URLEncoder.encode(zoneUrl, StandardCharsets.UTF_8));
        webDriver.get(authUrl);

        //we should now be in the Simple SAML PHP site
        webDriver.findElement(By.xpath(samlServerConfig.getLoginPromptXpathExpr()));
        sendCredentials("marissa5", "saml5");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Where to?");

        // do an auth code grant, passing the jsessionid
        Cookie cookie = webDriver.manage().getCookieNamed("JSESSIONID");
        System.out.printf("Cookie: %s=%s%n", cookie.getName(), cookie.getValue());

        serverRunning.setHostName("testzone1.localhost");
        Map<String, String> authCodeTokenResponse = IntegrationTestUtils.getAuthorizationCodeTokenMap(serverRunning,
                clientDetails.getClientId(),
                clientDetails.getClientSecret(),
                null,
                null,
                "token id_token",
                cookie.getValue(),
                zoneUrl,
                null,
                false);

        webDriver.get("%s/logout.do".formatted(baseUrl));
        webDriver.get("%s/logout.do".formatted(zoneUrl));

        //validate access token
        String accessToken = authCodeTokenResponse.get(ACCESS_TOKEN);
        Jwt accessTokenJwt = JwtHelper.decode(accessToken);
        Map<String, Object> accessTokenClaims = JsonUtils.readValue(accessTokenJwt.getClaims(), new TypeReference<>() {
        });
        List<String> accessTokenScopes = (List<String>) accessTokenClaims.get(ClaimConstants.SCOPE);
        // Check that the user had the roles scope, which is a pre-requisite for getting roles returned in the id_token
        assertThat(accessTokenScopes).contains(ClaimConstants.ROLES);

        //validate that we have an ID token, and that it contains costCenter and manager values

        String idToken = authCodeTokenResponse.get("id_token");
        assertThat(idToken).isNotNull();

        Jwt idTokenClaims = JwtHelper.decode(idToken);
        Map<String, Object> claims = JsonUtils.readValue(idTokenClaims.getClaims(), new TypeReference<>() {
        });

        assertThat(claims).containsKey(USER_ATTRIBUTES);
        Map<String, List<String>> userAttributes = (Map<String, List<String>>) claims.get(USER_ATTRIBUTES);
        assertThat(userAttributes.get(costCenters)).containsExactlyInAnyOrder(denverCo);
        assertThat(userAttributes.get(managers)).containsExactlyInAnyOrder(johnTheSloth, kariTheAntEater);

        //validate that ID token contains the correct roles
        String[] expectedRoles = new String[]{"saml.user", "saml.admin"};
        List<String> idTokenRoles = (List<String>) claims.get(ClaimConstants.ROLES);
        assertThat(idTokenRoles).containsExactlyInAnyOrder(expectedRoles);

        //validate user info
        UserInfoResponse userInfo = IntegrationTestUtils.getUserInfo(zoneUrl, authCodeTokenResponse.get("access_token"));

        Map<String, List<String>> userAttributeMap = userInfo.getUserAttributes();
        List<String> costCenterData = userAttributeMap.get(costCenters);
        List<String> managerData = userAttributeMap.get(managers);
        assertThat(costCenterData).containsExactlyInAnyOrder(denverCo);
        assertThat(managerData).containsExactlyInAnyOrder(johnTheSloth, kariTheAntEater);

        // user info should contain the user's roles
        List<String> userInfoRoles = userInfo.getRoles();
        assertThat(userInfoRoles).containsExactlyInAnyOrder(expectedRoles);
    }

    public SamlIdentityProviderDefinition createTestZone1IDP(String alias) {
        return createSimplePHPSamlIDP(alias, "testzone1", samlServerConfig.getSamlServerUrl());
    }

    private void sendCredentials(String username, String password, By loginButtonSelector) {
        webDriver.findElement(byUsername).clear();
        webDriver.findElement(byUsername).sendKeys(username);
        webDriver.findElement(byPassword).sendKeys(password);
        webDriver.clickAndWait(loginButtonSelector);
    }

    private void sendCredentials(String username, String password) {
        sendCredentials(username, password, By.id("submit_button"));
    }
}
