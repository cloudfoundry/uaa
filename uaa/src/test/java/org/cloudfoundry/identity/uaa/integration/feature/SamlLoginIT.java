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
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.account.UserInfoResponse;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.endpoints.LogoutDoEndpoint;
import org.cloudfoundry.identity.uaa.integration.endpoints.OauthAuthorizeEndpoint;
import org.cloudfoundry.identity.uaa.integration.endpoints.SamlLogoutAuthSourceEndpoint;
import org.cloudfoundry.identity.uaa.integration.pageObjects.FaviconElement;
import org.cloudfoundry.identity.uaa.integration.pageObjects.HomePage;
import org.cloudfoundry.identity.uaa.integration.pageObjects.LoginPage;
import org.cloudfoundry.identity.uaa.integration.pageObjects.Page;
import org.cloudfoundry.identity.uaa.integration.pageObjects.PasscodePage;
import org.cloudfoundry.identity.uaa.integration.pageObjects.SamlWelcomePage;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.integration.util.ScreenshotOnFail;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.client.test.TestAccounts;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.RetryRule;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.flywaydb.core.internal.util.StringUtils;
import org.hamcrest.Matchers;
import org.junit.Rule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.SAML_AUTH_SOURCE;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.SIMPLESAMLPHP_UAA_ACCEPTANCE;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.createSimplePHPSamlIDP;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.doesSupportZoneDNS;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.getZoneAdminToken;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.isMember;
import static org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken.ACCESS_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ATTRIBUTES;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.EMAIL_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_ATTRIBUTE_PREFIX;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
public class SamlLoginIT {

    public static final String MARISSA4_USERNAME = "marissa4";
    private static final String MARISSA4_PASSWORD = "saml2";
    public static final String MARISSA4_EMAIL = "marissa4@test.org";
    public static final String MARISSA2_USERNAME = "marissa2";
    private static final String MARISSA2_PASSWORD = "saml2";
    public static final String MARISSA3_USERNAME = "marissa3";
    private static final String MARISSA3_PASSWORD = "saml2";
    private static final String SAML_ORIGIN = "simplesamlphp";

    @Autowired
    @Rule
    public IntegrationTestRule integrationTestRule;

    @Rule
    public RetryRule retryRule = new RetryRule(3);

    @Rule
    public ScreenshotOnFail screenShootRule = new ScreenshotOnFail();

    @Autowired
    RestOperations restOperations;

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Autowired
    TestAccounts testAccounts;

    @Autowired
    TestClient testClient;

    ServerRunning serverRunning = ServerRunning.isRunning();

    @BeforeAll
    static void checkZoneDNSSupport() {
        assertTrue(doesSupportZoneDNS(), "Expected testzone1.localhost, testzone2.localhost, testzone3.localhost, testzone4.localhost to resolve to 127.0.0.1");
    }

    public static String getValidRandomIDPMetaData() {
        return MockMvcUtils.IDP_META_DATA.formatted(new RandomValueStringGenerator().generate());
    }

    @BeforeEach
    void setup() {
        String token = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");

        ScimGroup group = new ScimGroup(null, "zones.uaa.admin", null);
        IntegrationTestUtils.createGroup(token, "", baseUrl, group);

        group = new ScimGroup(null, "zones.testzone1.admin", null);
        IntegrationTestUtils.createGroup(token, "", baseUrl, group);

        group = new ScimGroup(null, "zones.testzone2.admin", null);
        IntegrationTestUtils.createGroup(token, "", baseUrl, group);

        group = new ScimGroup(null, "zones.testzone3.admin", null);
        IntegrationTestUtils.createGroup(token, "", baseUrl, group);

        group = new ScimGroup(null, "zones.testzone4.admin", null);
        IntegrationTestUtils.createGroup(token, "", baseUrl, group);
    }

    @AfterEach
    void cleanup() {
        String token = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");
        for (String zoneId : Arrays.asList("testzone1", "testzone2", "testzone3", "testzone4", "uaa")) {
            String groupId = IntegrationTestUtils.getGroup(token, "", baseUrl, "zones.%s.admin".formatted(zoneId)).getId();
            IntegrationTestUtils.deleteGroup(token, "", baseUrl, groupId);

            try {
                IntegrationTestUtils.deleteZone(baseUrl, zoneId, token);
                IntegrationTestUtils.deleteProvider(token, baseUrl, "uaa", zoneId + ".cloudfoundry-saml-login");
            } catch (Exception ignored) {
            }
        }
    }

    @BeforeEach
    void clearWebDriverOfCookies() {
        screenShootRule.setWebDriver(webDriver);
        for (String domain : Arrays.asList("localhost", "testzone1.localhost", "testzone2.localhost", "testzone3.localhost", "testzone4.localhost")) {
            LogoutDoEndpoint.logout(webDriver, baseUrl.replace("localhost", domain));
            new Page(webDriver).clearCookies();
        }
        SamlLogoutAuthSourceEndpoint.logoutAuthSource_goesToSamlWelcomePage(webDriver, SIMPLESAMLPHP_UAA_ACCEPTANCE, SAML_AUTH_SOURCE);
    }

    @Test
    void samlSPMetadata() {
        RestTemplate request = new RestTemplate();
        ResponseEntity<String> response = request.getForEntity(
                "%s/saml/metadata".formatted(baseUrl), String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        String metadataXml = response.getBody();

        // The SAML SP metadata should match the following UAA configs:
        // login.entityID
        assertThat(metadataXml).contains("entityID=\"cloudfoundry-saml-login\"")
                // TODO: Are DigestMethod and SignatureMethod needed?
                //  login.saml.signatureAlgorithm
                //.contains("<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>")
                //.contains("<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>")
                // login.saml.signRequest
                .contains("AuthnRequestsSigned=\"true\"")
                // login.saml.wantAssertionSigned
                .contains("WantAssertionsSigned=\"true\"")
                // login.saml.nameID
                .contains("<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>");
    }

    @Test
    void contentTypes() {
        String loginUrl = "%s/login".formatted(baseUrl);
        HttpHeaders jsonHeaders = new HttpHeaders();
        jsonHeaders.add("Accept", "application/json");
        ResponseEntity<Map> jsonResponseEntity = restOperations.exchange(loginUrl,
                HttpMethod.GET,
                new HttpEntity<>(jsonHeaders),
                Map.class);
        assertThat(jsonResponseEntity.getHeaders().get("Content-Type").get(0)).contains(APPLICATION_JSON_VALUE);

        HttpHeaders htmlHeaders = new HttpHeaders();
        htmlHeaders.add("Accept", "text/html");
        ResponseEntity<Void> htmlResponseEntity = restOperations.exchange(loginUrl,
                HttpMethod.GET,
                new HttpEntity<>(htmlHeaders),
                Void.class);
        assertThat(htmlResponseEntity.getHeaders().get("Content-Type").get(0)).contains(TEXT_HTML_VALUE);

        HttpHeaders defaultHeaders = new HttpHeaders();
        defaultHeaders.add("Accept", "*/*");
        ResponseEntity<Void> defaultResponseEntity = restOperations.exchange(loginUrl,
                HttpMethod.GET,
                new HttpEntity<>(defaultHeaders),
                Void.class);
        assertThat(defaultResponseEntity.getHeaders().get("Content-Type").get(0)).contains(TEXT_HTML_VALUE);
    }

    @Test
    void simpleSamlPhpPasscodeRedirect() throws Exception {
        createIdentityProvider(SAML_ORIGIN);

        PasscodePage.requestPasscode_goesToLoginPage(webDriver, baseUrl)
                .clickSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .login_goesToPasscodePage(testAccounts.getUserName(), testAccounts.getPassword());
    }

    @Test
    @Disabled("SAML test fails")
    void simpleSamlLoginWithAddShadowUserOnLoginFalse() throws Exception {
        // Deleting marissa@test.org from simplesamlphp because previous SAML authentications automatically
        // create a UAA user with the email address as the username.
        deleteUser(SAML_ORIGIN, testAccounts.getEmail());

        IdentityProvider<SamlIdentityProviderDefinition> provider = IntegrationTestUtils.createIdentityProvider(SAML_ORIGIN, false, baseUrl, serverRunning);
        String clientId = "app-addnew-false" + new RandomValueStringGenerator().generate();
        String redirectUri = "http://nosuchhostname:0/nosuchendpoint";
        createClientAndSpecifyProvider(clientId, provider, redirectUri);

        OauthAuthorizeEndpoint
                .authorize_goesToSamlLoginPage(webDriver, baseUrl, redirectUri, clientId, "code")
                .login_goesToCustomErrorPage(
                        testAccounts.getUserName(),
                        testAccounts.getPassword(),
                        containsString("%s?error=access_denied&error_description=SAML+user+does+not+exist.+You+can+correct+this+by+creating+a+shadow+user+for+the+SAML+user.".formatted(redirectUri)));
    }

    @Test
    @Disabled("SAML test fails: Requires zones")
    void incorrectResponseFromSamlIdpShowErrorFromSaml() {
        String zoneId = "testzone3";
        String zoneUrl = baseUrl.replace("localhost", "%s.localhost".formatted(zoneId));

        //identity client token
        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
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

        SamlIdentityProviderDefinition samlIdentityProviderDefinition = createSimplePHPSamlIDP(SAML_ORIGIN, "testzone3");
        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setIdentityZoneId(zoneId);
        provider.setType(OriginKeys.SAML);
        provider.setActive(true);
        provider.setConfig(samlIdentityProviderDefinition);
        provider.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        provider.setName("simplesamlphp for testzone2");

        IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);

        HomePage.tryToGoHome_redirectsToLoginPage(webDriver, zoneUrl)
                .clickSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .login_goesToSamlErrorPage(testAccounts.getUserName(), testAccounts.getPassword())
                .validatePageSource(containsString("No local entity found for alias invalid, verify your configuration"));
    }

    @Test
    void simpleSamlPhpLogin() throws Exception {
        createIdentityProvider(SAML_ORIGIN);

        Long beforeTest = System.currentTimeMillis();
        LoginPage.go(webDriver, baseUrl)
                .clickSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .login_goesToHomePage(testAccounts.getUserName(), testAccounts.getPassword());
        Long afterTest = System.currentTimeMillis();

        String zoneAdminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "admin", "adminsecret");
        ScimUser user = IntegrationTestUtils.getUser(zoneAdminToken, baseUrl, SAML_ORIGIN, testAccounts.getEmail());
        IntegrationTestUtils.validateUserLastLogon(user, beforeTest, afterTest);
    }

    @Test
    void simpleSamlPhpLoginDisplaysLastLogin() throws Exception {
        createIdentityProvider(SAML_ORIGIN);

        Long beforeTest = System.currentTimeMillis();
        HomePage homePage = LoginPage.go(webDriver, baseUrl)
                .clickSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .login_goesToHomePage(testAccounts.getUserName(), testAccounts.getPassword())
                .logout_goesToLoginPage()
                .clickSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .login_goesToHomePage(testAccounts.getUserName(), testAccounts.getPassword());
        assertThat(homePage.hasLastLoginTime()).isTrue();

        Long afterTest = System.currentTimeMillis();
        String zoneAdminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "admin", "adminsecret");
        ScimUser user = IntegrationTestUtils.getUser(zoneAdminToken, baseUrl, SAML_ORIGIN, testAccounts.getEmail());
        IntegrationTestUtils.validateUserLastLogon(user, beforeTest, afterTest);
    }

    @Test
    void singleLogout() throws Exception {
        createIdentityProvider(SAML_ORIGIN);

        LoginPage.go(webDriver, baseUrl)
                .clickSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .login_goesToHomePage(testAccounts.getUserName(), testAccounts.getPassword())
                .logout_goesToLoginPage()
                .clickSamlLink_goesToSamlLoginPage(SAML_ORIGIN);
    }

    @Test
    void idpInitiatedLogout() throws Exception {
        createIdentityProvider(SAML_ORIGIN);

        LoginPage.go(webDriver, baseUrl)
                .clickSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .login_goesToHomePage(testAccounts.getUserName(), testAccounts.getPassword());

        // Logout via IDP
        webDriver.get("%s/saml2/idp/SingleLogoutService.php?ReturnTo=%1$s/module.php/core/welcome".formatted(SIMPLESAMLPHP_UAA_ACCEPTANCE));
        // UAA should redirect to the welcome page
        new SamlWelcomePage(webDriver);

        // UAA Should no longer be logged in
        HomePage.tryToGoHome_redirectsToLoginPage(webDriver, baseUrl);
    }

    @Test
    @Disabled("SAML test fails: Requires zones and logout")
    void singleLogoutWithNoLogoutUrlOnIDPWithLogoutRedirect() {
        String zoneId = "testzone2";
        String zoneUrl = baseUrl.replace("localhost", zoneId + ".localhost");

        //identity client token
        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );

        //admin client token - to create users
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );

        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.getLinks().getLogout().setDisableRedirectParameter(false);
        config.getCorsPolicy().getDefaultConfiguration().setAllowedMethods(
                List.of(GET.toString(), POST.toString()));

        //create the zone
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
        SamlIdentityProviderDefinition providerDefinition = createIDPWithNoSLOSConfigured();
        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setIdentityZoneId(zoneId);
        provider.setType(OriginKeys.SAML);
        provider.setActive(true);
        provider.setConfig(providerDefinition);
        provider.setOriginKey(providerDefinition.getIdpEntityAlias());
        provider.setName("simplesamlphp for uaa");
        IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);

        LoginPage loginPage = LoginPage.go(webDriver, zoneUrl);
        loginPage.validateTitle(Matchers.containsString("testzone2"));
        loginPage.clickSamlLink_goesToSamlLoginPage("simplesamlphp")
                .login_goesToHomePage(testAccounts.getUserName(), testAccounts.getPassword());

        String redirectUrl = zoneUrl + "/login?test=test";
        UaaClientDetails clientDetails = new UaaClientDetails("test-logout-redirect", null, null, GRANT_TYPE_AUTHORIZATION_CODE, null);
        clientDetails.setRegisteredRedirectUri(Collections.singleton(redirectUrl));
        clientDetails.setClientSecret("secret");
        IntegrationTestUtils.createOrUpdateClient(zoneAdminToken, baseUrl, zoneId, clientDetails);

        LogoutDoEndpoint.logout_goesToLoginPage(webDriver, zoneUrl, redirectUrl, "test-logout-redirect")
                .validateUrl(equalTo(redirectUrl));
    }

    @Test
    void singleLogoutWithNoLogoutUrlOnIDP() throws Exception {
        SamlIdentityProviderDefinition providerDefinition = createIDPWithNoSLOSConfigured();
        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setIdentityZoneId(OriginKeys.UAA);
        provider.setType(OriginKeys.SAML);
        provider.setActive(true);
        provider.setConfig(providerDefinition);
        provider.setOriginKey(providerDefinition.getIdpEntityAlias());
        provider.setName("simplesamlphp for uaa");

        String zoneAdminToken = getZoneAdminToken(baseUrl, serverRunning);
        IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);

        LoginPage.go(webDriver, baseUrl)
                .clickSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .login_goesToHomePage(testAccounts.getUserName(), testAccounts.getPassword())
                .logout_goesToLoginPage()
                // Local Logout, but not logged out of IDP, login should skip U/P prompt
                .clickSamlLink_goesToHomePage(SAML_ORIGIN);
    }

    @Test
    void groupIntegration() throws Exception {
        createIdentityProvider(SAML_ORIGIN);
        LoginPage.go(webDriver, baseUrl)
                .clickSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .login_goesToHomePage(MARISSA4_USERNAME, MARISSA4_PASSWORD);
    }

    @Test
    void faviconShouldNotSave() throws Exception {
        createIdentityProvider(SAML_ORIGIN);
        FaviconElement.getDefaultIcon(webDriver, baseUrl);
        LoginPage.go(webDriver, baseUrl)
                .clickSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .login_goesToHomePage(MARISSA4_USERNAME, MARISSA4_PASSWORD);
    }

    protected IdentityProvider<SamlIdentityProviderDefinition> createIdentityProvider(String originKey) throws Exception {
        return IntegrationTestUtils.createIdentityProvider(originKey, true, baseUrl, serverRunning);
    }

    protected void createClientAndSpecifyProvider(String clientId, IdentityProvider<SamlIdentityProviderDefinition> provider,
                                                  String redirectUri) {

        IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "identity", "identitysecret")
        );
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );
        String email = new RandomValueStringGenerator().generate() + "@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl, email, "firstname", "lastname", email, true);
        String groupId = IntegrationTestUtils.findGroupId(adminClient, baseUrl, "zones." + OriginKeys.UAA + ".admin");
        IntegrationTestUtils.addMemberToGroup(adminClient, baseUrl, user.getId(), groupId);

        String zoneAdminToken =
                IntegrationTestUtils.getAccessTokenByAuthCode(serverRunning,
                        UaaTestAccounts.standard(serverRunning),
                        "identity",
                        "identitysecret",
                        email,
                        "secr3T");

        UaaClientDetails clientDetails =
                new UaaClientDetails(clientId, null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource", redirectUri);
        clientDetails.setClientSecret("secret");
        List<String> idps = Collections.singletonList(provider.getOriginKey());
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);
        clientDetails.setAutoApproveScopes(Collections.singleton("true"));
        IntegrationTestUtils.createClient(zoneAdminToken, baseUrl, clientDetails);
    }

    protected void deleteUser(String origin, String username) {
        String zoneAdminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning,
                "admin", "adminsecret");

        String userId = IntegrationTestUtils.getUserId(zoneAdminToken, baseUrl, origin, username);
        if (null == userId) {
            return;
        }

        IntegrationTestUtils.deleteUser(zoneAdminToken, baseUrl, userId);
    }

    @Test
    @Disabled("SAML test fails: Requires zones")
    void samlInvitationAutomaticRedirectInZone2() {
        performSamlInvitationAutomaticRedirectInZone2(MARISSA2_USERNAME, MARISSA2_PASSWORD, true);
        performSamlInvitationAutomaticRedirectInZone2(MARISSA2_USERNAME, MARISSA2_PASSWORD, true);
        performSamlInvitationAutomaticRedirectInZone2(MARISSA2_USERNAME, MARISSA2_PASSWORD, true);

        performSamlInvitationAutomaticRedirectInZone2(MARISSA3_USERNAME, MARISSA3_PASSWORD, false);
        performSamlInvitationAutomaticRedirectInZone2(MARISSA3_USERNAME, MARISSA3_PASSWORD, false);
        performSamlInvitationAutomaticRedirectInZone2(MARISSA3_USERNAME, MARISSA3_PASSWORD, false);
    }

    public void performSamlInvitationAutomaticRedirectInZone2(String username, String password, boolean emptyList) {
        //ensure we are able to resolve DNS for hostname testzone1.localhost
        String zoneId = "testzone2";
        String zoneUrl = baseUrl.replace("localhost", zoneId + ".localhost");

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

        SamlIdentityProviderDefinition samlIdentityProviderDefinition = createTestZone2IDP(SAML_ORIGIN);
        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setIdentityZoneId(zoneId);
        provider.setType(OriginKeys.SAML);
        provider.setActive(true);
        provider.setConfig(samlIdentityProviderDefinition);
        provider.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        provider.setName("simplesamlphp for testzone2");

        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertThat(provider.getConfig().getIdpEntityAlias()).isEqualTo(provider.getOriginKey());

        UaaIdentityProviderDefinition uaaDefinition = new UaaIdentityProviderDefinition(
                new PasswordPolicy(1, 255, 0, 0, 0, 0, 12),
                new LockoutPolicy(10, 10, 10)
        );
        uaaDefinition.setEmailDomain(emptyList ? Collections.emptyList() : Arrays.asList("*.*", "*.*.*"));
        IdentityProvider<UaaIdentityProviderDefinition> uaaProvider = (IdentityProvider<UaaIdentityProviderDefinition>) IntegrationTestUtils.getProvider(zoneAdminToken, baseUrl, zoneId, OriginKeys.UAA);
        uaaProvider.setConfig(uaaDefinition);
        uaaProvider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, uaaProvider);

        UaaClientDetails uaaAdmin = new UaaClientDetails("admin", "", "", "client_credentials", "uaa.admin,scim.read,scim.write");
        uaaAdmin.setClientSecret("adminsecret");
        IntegrationTestUtils.createOrUpdateClient(zoneAdminToken, baseUrl, zoneId, uaaAdmin);

        String uaaAdminToken = testClient.getOAuthAccessToken(zoneUrl, "admin", "adminsecret", "client_credentials", "");

        String useremail = username + "@test.org";
        String code = InvitationsIT.createInvitation(zoneUrl, useremail, useremail, samlIdentityProviderDefinition.getIdpEntityAlias(), "", uaaAdminToken, uaaAdminToken);
        String invitedUserId = IntegrationTestUtils.getUserId(uaaAdminToken, zoneUrl, samlIdentityProviderDefinition.getIdpEntityAlias(), useremail);
        String existingUserId = IntegrationTestUtils.getUserId(uaaAdminToken, zoneUrl, samlIdentityProviderDefinition.getIdpEntityAlias(), useremail);
        webDriver.get(zoneUrl + "/logout.do");
        webDriver.get(zoneUrl + "/invitations/accept?code=" + code);

        //redirected to saml login
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        sendCredentials(username, password);

        //we should now be on the login page because we don't have a redirect
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Where to?");

        uaaProvider.setConfig((UaaIdentityProviderDefinition) uaaDefinition.setEmailDomain(null));
        IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, uaaProvider);

        String acceptedUserId = IntegrationTestUtils.getUserId(uaaAdminToken, zoneUrl, samlIdentityProviderDefinition.getIdpEntityAlias(), useremail);
        if (StringUtils.hasText(existingUserId)) {
            assertThat(existingUserId).isEqualTo(acceptedUserId);
        } else {
            assertThat(acceptedUserId).isEqualTo(invitedUserId);
        }

        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(zoneUrl + "/logout.do");
        SamlLogoutAuthSourceEndpoint.logoutAuthSource_goesToSamlWelcomePage(webDriver, SIMPLESAMLPHP_UAA_ACCEPTANCE, SAML_AUTH_SOURCE);
    }

    @Test
    @Disabled("SAML test fails: Requires zones")
    void relayStateRedirectFromIdp() {
        //ensure we are able to resolve DNS for hostname testzone1.localhost
        String zoneId = "testzone1";

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

        SamlIdentityProviderDefinition samlIdentityProviderDefinition = createTestZone1IDP(SAML_ORIGIN);
        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setIdentityZoneId(zoneId);
        provider.setType(OriginKeys.SAML);
        provider.setActive(true);
        provider.setConfig(samlIdentityProviderDefinition);
        provider.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        provider.setName("simplesamlphp for testzone1");

        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertThat(provider.getConfig().getIdpEntityAlias()).isEqualTo(provider.getOriginKey());

        String zoneUrl = baseUrl.replace("localhost", "testzone1.localhost");

        webDriver.get(zoneUrl + "/logout.do");

        String samlUrl = SIMPLESAMLPHP_UAA_ACCEPTANCE + "/saml2/idp/SSOService.php?"
                + "spentityid=testzone1.cloudfoundry-saml-login&"
                + "RelayState=https://www.google.com";
        webDriver.get(samlUrl);

        //we should now be in the Simple SAML PHP site
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        sendCredentials(testAccounts.getUserName(), "koala");

        assertThat(webDriver.getCurrentUrl()).startsWith("https://www.google.com");
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(zoneUrl + "/logout.do");
    }

    @Test
    @Disabled("SAML test fails: Requires zones")
    void samlLoginClientIDPAuthorizationAutomaticRedirectInZone1() {
        //ensure we are able to resolve DNS for hostname testzone1.localhost
        String zoneId = "testzone1";

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

        SamlIdentityProviderDefinition samlIdentityProviderDefinition = createTestZone1IDP(SAML_ORIGIN);
        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setIdentityZoneId(zoneId);
        provider.setType(OriginKeys.SAML);
        provider.setActive(true);
        provider.setConfig(samlIdentityProviderDefinition);
        provider.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        provider.setName("simplesamlphp for testzone1");

        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertThat(provider.getConfig().getIdpEntityAlias()).isEqualTo(provider.getOriginKey());

        List<String> idps = Collections.singletonList(provider.getOriginKey());
        String clientId = UUID.randomUUID().toString();
        String zoneUrl = baseUrl.replace("localhost", "testzone1.localhost");
        UaaClientDetails clientDetails = new UaaClientDetails(clientId, null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.none", zoneUrl);
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);
        clientDetails.setAutoApproveScopes(Collections.singleton("true"));
        IntegrationTestUtils.createClientAsZoneAdmin(zoneAdminToken, baseUrl, zoneId, clientDetails);

        webDriver.get(zoneUrl + "/logout.do");

        String authUrl = zoneUrl + "/oauth/authorize?client_id=" + clientId + "&redirect_uri=" + URLEncoder.encode(zoneUrl, StandardCharsets.UTF_8) + "&response_type=code&state=8tp0tR";
        webDriver.get(authUrl);

        //we should now be in the Simple SAML PHP site
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        sendCredentials(testAccounts.getUserName(), "koala");

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Where to?");
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(zoneUrl + "/logout.do");
    }

    @Test
    @Disabled("SAML test fails: Requires zones and logout")
    void samlLoginMapGroupsInZone1() {
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

        SamlIdentityProviderDefinition samlIdentityProviderDefinition = createTestZone1IDP(SAML_ORIGIN);
        samlIdentityProviderDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, "groups");
        samlIdentityProviderDefinition.addWhiteListedGroup("saml.user");
        samlIdentityProviderDefinition.addWhiteListedGroup("saml.admin");

        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setIdentityZoneId(zoneId);
        provider.setType(OriginKeys.SAML);
        provider.setActive(true);
        provider.setConfig(samlIdentityProviderDefinition);
        provider.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        provider.setName("simplesamlphp for testzone1");

        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertThat(provider.getConfig().getIdpEntityAlias()).isEqualTo(provider.getOriginKey());

        List<String> idps = Collections.singletonList(provider.getOriginKey());

        String adminClientInZone = new RandomValueStringGenerator().generate();
        UaaClientDetails clientDetails = new UaaClientDetails(adminClientInZone, null, "openid", "authorization_code,client_credentials", "uaa.admin,scim.read,scim.write", zoneUrl);
        clientDetails.setClientSecret("secret");
        clientDetails.setAutoApproveScopes(Collections.singleton("true"));
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);

        clientDetails = IntegrationTestUtils.createClientAsZoneAdmin(zoneAdminToken, baseUrl, zoneId, clientDetails);
        String adminTokenInZone = IntegrationTestUtils.getClientCredentialsToken(zoneUrl, clientDetails.getClientId(), "secret");

        ScimGroup uaaSamlUserGroup = new ScimGroup(null, "uaa.saml.user", zoneId);
        uaaSamlUserGroup = IntegrationTestUtils.createOrUpdateGroup(adminTokenInZone, null, zoneUrl, uaaSamlUserGroup);

        ScimGroup uaaSamlAdminGroup = new ScimGroup(null, "uaa.saml.admin", zoneId);
        uaaSamlAdminGroup = IntegrationTestUtils.createOrUpdateGroup(adminTokenInZone, null, zoneUrl, uaaSamlAdminGroup);

        ScimGroupExternalMember uaaSamlUserMapping = new ScimGroupExternalMember(uaaSamlUserGroup.getId(), "saml.user");
        uaaSamlUserMapping.setOrigin(provider.getOriginKey());
        ScimGroupExternalMember uaaSamlAdminMapping = new ScimGroupExternalMember(uaaSamlAdminGroup.getId(), "saml.admin");
        uaaSamlAdminMapping.setOrigin(provider.getOriginKey());
        IntegrationTestUtils.mapExternalGroup(zoneAdminToken, zoneId, baseUrl, uaaSamlUserMapping);
        IntegrationTestUtils.mapExternalGroup(zoneAdminToken, zoneId, baseUrl, uaaSamlAdminMapping);

        webDriver.get(zoneUrl + "/logout.do");

        String authUrl = zoneUrl + "/oauth/authorize?client_id=" + clientDetails.getClientId() + "&redirect_uri=" + URLEncoder.encode(zoneUrl, StandardCharsets.UTF_8) + "&response_type=code&state=8tp0tR";
        webDriver.get(authUrl);

        //we should now be in the Simple SAML PHP site
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        sendCredentials(MARISSA4_USERNAME, MARISSA4_PASSWORD);

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Where to?");
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(zoneUrl + "/logout.do");

        //validate that the groups were mapped
        String samlUserId = IntegrationTestUtils.getUserId(adminTokenInZone, zoneUrl, provider.getOriginKey(), MARISSA4_EMAIL);
        uaaSamlUserGroup = IntegrationTestUtils.getGroup(adminTokenInZone, null, zoneUrl, "uaa.saml.user");
        uaaSamlAdminGroup = IntegrationTestUtils.getGroup(adminTokenInZone, null, zoneUrl, "uaa.saml.admin");
        IdentityProvider<SamlIdentityProviderDefinition> finalProvider = provider;
        assertThat(isMember(samlUserId, uaaSamlUserGroup)).isTrue();
        assertThat(uaaSamlUserGroup.getMembers().stream())
                .as("Expect saml user members to have origin: " + finalProvider.getOriginKey())
                .allMatch(p -> finalProvider.getOriginKey().equals(p.getOrigin()));
        assertThat(isMember(samlUserId, uaaSamlAdminGroup)).isTrue();
        assertThat(uaaSamlAdminGroup.getMembers().stream())
                .as("Expect admin members to have origin: " + finalProvider.getOriginKey())
                .allMatch(p -> finalProvider.getOriginKey().equals(p.getOrigin()));
    }

    @Test
    @Disabled("SAML test fails: Requires zones and logout")
    void samlLoginCustomUserAttributesAndRolesInIDToken() throws Exception {

        final String COST_CENTER = "costCenter";
        final String COST_CENTERS = "costCenters";
        final String DENVER_CO = "Denver,CO";
        final String MANAGER = "manager";
        final String MANAGERS = "managers";
        final String JOHN_THE_SLOTH = "John the Sloth";
        final String KARI_THE_ANT_EATER = "Kari the Ant Eater";

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
        samlIdentityProviderDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX + COST_CENTERS, COST_CENTER);
        samlIdentityProviderDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX + MANAGERS, MANAGER);

        // External groups will only appear as roles if they are whitelisted
        samlIdentityProviderDefinition.setExternalGroupsWhitelist(List.of("*"));

        // External groups will only be found when there is a configured attribute name for them
        samlIdentityProviderDefinition.addAttributeMapping("external_groups", Collections.singletonList("groups"));

        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider();
        provider.setIdentityZoneId(zoneId);
        provider.setType(OriginKeys.SAML);
        provider.setActive(true);
        provider.setConfig(samlIdentityProviderDefinition);
        provider.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        provider.setName("simplesamlphp for testzone1");

        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertThat(provider.getConfig().getIdpEntityAlias()).isEqualTo(provider.getOriginKey());

        List<String> idps = Collections.singletonList(provider.getOriginKey());

        // set up a test client
        String adminClientInZone = new RandomValueStringGenerator().generate();
        UaaClientDetails clientDetails = new UaaClientDetails(adminClientInZone, null, "openid,user_attributes,roles", "authorization_code,client_credentials", "uaa.admin,scim.read,scim.write,uaa.resource", zoneUrl);
        clientDetails.setClientSecret("secret");
        clientDetails.setAutoApproveScopes(Collections.singleton("true"));
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);

        clientDetails = IntegrationTestUtils.createClientAsZoneAdmin(zoneAdminToken, baseUrl, zoneId, clientDetails);
        clientDetails.setClientSecret("secret");

        IntegrationTestUtils.getClientCredentialsToken(zoneUrl, clientDetails.getClientId(), "secret");

        webDriver.get(zoneUrl + "/logout.do");

        String authUrl = zoneUrl + "/oauth/authorize?response_type=code&state=8tp0tR&client_id=" + clientDetails.getClientId() + "&redirect_uri=" + URLEncoder.encode(zoneUrl, StandardCharsets.UTF_8);
        webDriver.get(authUrl);
        //we should now be in the Simple SAML PHP site
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        sendCredentials("marissa5", "saml5");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Where to?");

        Cookie cookie = webDriver.manage().getCookieNamed("JSESSIONID");

        //do an auth code grant
        //pass up the jsessionid
        System.out.println("cookie = " + "%s=%s".formatted(cookie.getName(), cookie.getValue()));

        serverRunning.setHostName("testzone1.localhost");
        Map<String, String> authCodeTokenResponse = IntegrationTestUtils.getAuthorizationCodeTokenMap(serverRunning,
                UaaTestAccounts.standard(serverRunning),
                clientDetails.getClientId(),
                clientDetails.getClientSecret(),
                null,
                null,
                "token id_token",
                cookie.getValue(),
                zoneUrl,
                null,
                false);

        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(zoneUrl + "/logout.do");

        //validate access token
        String accessToken = authCodeTokenResponse.get(ACCESS_TOKEN);
        Jwt accessTokenJwt = JwtHelper.decode(accessToken);
        Map<String, Object> accessTokenClaims = JsonUtils.readValue(accessTokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {
        });
        List<String> accessTokenScopes = (List<String>) accessTokenClaims.get(ClaimConstants.SCOPE);
        // Check that the user had the roles scope, which is a pre-requisite for getting roles returned in the id_token
        assertThat(accessTokenScopes).contains(ClaimConstants.ROLES);

        //validate that we have an ID token, and that it contains costCenter and manager values

        String idToken = authCodeTokenResponse.get("id_token");
        assertThat(idToken).isNotNull();

        Jwt idTokenClaims = JwtHelper.decode(idToken);
        Map<String, Object> claims = JsonUtils.readValue(idTokenClaims.getClaims(), new TypeReference<Map<String, Object>>() {
        });

        assertThat(claims.get(USER_ATTRIBUTES)).isNotNull();
        Map<String, List<String>> userAttributes = (Map<String, List<String>>) claims.get(USER_ATTRIBUTES);
        assertThat(userAttributes.get(COST_CENTERS)).containsExactlyInAnyOrder(DENVER_CO);
        assertThat(userAttributes.get(MANAGERS)).containsExactlyInAnyOrder(JOHN_THE_SLOTH, KARI_THE_ANT_EATER);

        //validate that ID token contains the correct roles
        String[] expectedRoles = new String[]{"saml.user", "saml.admin"};
        List<String> idTokenRoles = (List<String>) claims.get(ClaimConstants.ROLES);
        assertThat(idTokenRoles).containsExactlyInAnyOrder(expectedRoles);

        //validate user info
        UserInfoResponse userInfo = IntegrationTestUtils.getUserInfo(zoneUrl, authCodeTokenResponse.get("access_token"));

        Map<String, List<String>> userAttributeMap = userInfo.getUserAttributes();
        List<String> costCenterData = userAttributeMap.get(COST_CENTERS);
        List<String> managerData = userAttributeMap.get(MANAGERS);
        assertThat(costCenterData).containsExactlyInAnyOrder(DENVER_CO);
        assertThat(managerData).containsExactlyInAnyOrder(JOHN_THE_SLOTH, KARI_THE_ANT_EATER);

        // user info should contain the user's roles
        List<String> userInfoRoles = userInfo.getRoles();
        assertThat(userInfoRoles).containsExactlyInAnyOrder(expectedRoles);
    }

    @Test
    @Disabled("SAML test fails: Requires zones and logout")
    void samlLoginEmailInIDTokenWhenUserIDIsNotEmail() {

        //ensure we are able to resolve DNS for hostname testzone1.localhost
        String zoneId = "testzone4";
        String zoneUrl = baseUrl.replace("localhost", zoneId + ".localhost");

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

        SamlIdentityProviderDefinition samlIdentityProviderDefinition = createTestZoneIDP(SAML_ORIGIN, zoneId);
        samlIdentityProviderDefinition.addAttributeMapping(EMAIL_ATTRIBUTE_NAME, "emailAddress");

        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setType(OriginKeys.SAML);
        provider.setActive(true);
        provider.setConfig(samlIdentityProviderDefinition);
        provider.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        provider.setName("simplesamlphp for " + zoneId);

        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertThat(provider.getConfig().getIdpEntityAlias()).isEqualTo(provider.getOriginKey());

        List<String> idps = Collections.singletonList(provider.getOriginKey());

        String adminClientInZone = new RandomValueStringGenerator().generate();
        UaaClientDetails clientDetails = new UaaClientDetails(adminClientInZone, null, "openid,user_attributes", "authorization_code,client_credentials", "uaa.admin,scim.read,scim.write,uaa.resource", zoneUrl);
        clientDetails.setClientSecret("secret");
        clientDetails.setAutoApproveScopes(Collections.singleton("true"));
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);

        clientDetails = IntegrationTestUtils.createClientAsZoneAdmin(zoneAdminToken, baseUrl, zoneId, clientDetails);
        clientDetails.setClientSecret("secret");

        IntegrationTestUtils.getClientCredentialsToken(zoneUrl, clientDetails.getClientId(), "secret");

        webDriver.get(zoneUrl + "/logout.do");

        String authUrl = zoneUrl + "/oauth/authorize?client_id=" + clientDetails.getClientId() + "&redirect_uri=" + URLEncoder.encode(zoneUrl, StandardCharsets.UTF_8) + "&response_type=code&state=8tp0tR";
        webDriver.get(authUrl);
        //we should now be in the Simple SAML PHP site
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        sendCredentials("marissa6", "saml6");
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Where to?");

        Cookie cookie = webDriver.manage().getCookieNamed("JSESSIONID");

        //do an auth code grant
        //pass up the jsessionid
        System.out.println("cookie = " + "%s=%s".formatted(cookie.getName(), cookie.getValue()));

        serverRunning.setHostName(zoneId + ".localhost");
        Map<String, String> authCodeTokenResponse = IntegrationTestUtils.getAuthorizationCodeTokenMap(serverRunning,
                UaaTestAccounts.standard(serverRunning),
                clientDetails.getClientId(),
                clientDetails.getClientSecret(),
                null,
                null,
                "token id_token",
                cookie.getValue(),
                zoneUrl,
                null,
                false);

        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(zoneUrl + "/logout.do");

        //validate that we have an ID token, and that it contains costCenter and manager values

        String idToken = authCodeTokenResponse.get("id_token");
        assertThat(idToken).isNotNull();

        Jwt idTokenClaims = JwtHelper.decode(idToken);
        Map<String, Object> claims = JsonUtils.readValue(idTokenClaims.getClaims(), new TypeReference<Map<String, Object>>() {
        });

        assertThat(claims).containsKey(USER_ATTRIBUTES)
                .containsEntry(ClaimConstants.USER_NAME, "marissa6")
                .containsEntry(ClaimConstants.EMAIL, "marissa6@test.org");
    }

    @Test
    @Disabled("SAML test fails: Requires zones and logout")
    void simpleSamlPhpLoginInTestZone1Works() {
        String zoneId = "testzone1";

        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );

        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.getCorsPolicy().getDefaultConfiguration().setAllowedMethods(List.of(GET.toString(), POST.toString()));
        IdentityZone zone = IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId, config);
        String email = new RandomValueStringGenerator().generate() + "@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl, email, "firstname", "lastname", email, true);
        String groupId = IntegrationTestUtils.findGroupId(adminClient, baseUrl, "zones." + zoneId + ".admin");
        IntegrationTestUtils.addMemberToGroup(adminClient, baseUrl, user.getId(), groupId);

        String zoneAdminToken =
                IntegrationTestUtils.getAccessTokenByAuthCode(serverRunning,
                        UaaTestAccounts.standard(serverRunning),
                        "identity",
                        "identitysecret",
                        email,
                        "secr3T");

        SamlIdentityProviderDefinition samlIdentityProviderDefinition = createTestZone1IDP(SAML_ORIGIN);
        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setIdentityZoneId(zoneId);
        provider.setType(OriginKeys.SAML);
        provider.setActive(true);
        provider.setConfig(samlIdentityProviderDefinition);
        provider.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        provider.setName("simplesamlphp for testzone1");

        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);

        //we have to create two providers to avoid automatic redirect
        SamlIdentityProviderDefinition samlIdentityProviderDefinition1 = samlIdentityProviderDefinition.clone();
        samlIdentityProviderDefinition1.setIdpEntityAlias(samlIdentityProviderDefinition.getIdpEntityAlias() + "-1");
        samlIdentityProviderDefinition1.setMetaDataLocation(getValidRandomIDPMetaData());
        IdentityProvider<SamlIdentityProviderDefinition> provider1 = new IdentityProvider<>();
        provider1.setIdentityZoneId(zoneId);
        provider1.setType(OriginKeys.SAML);
        provider1.setActive(true);
        provider1.setConfig(samlIdentityProviderDefinition1);
        provider1.setOriginKey(samlIdentityProviderDefinition1.getIdpEntityAlias());
        provider1.setName("simplesamlphp 1 for testzone1");
        IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider1);

        assertThat(provider.getId()).isNotNull();

        String testZone1Url = baseUrl.replace("localhost", zoneId + ".localhost");
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(testZone1Url + "/logout.do");
        webDriver.get(testZone1Url + "/login");
        assertThat(webDriver.getTitle()).isEqualTo(zone.getName());

        List<WebElement> elements = webDriver.findElements(By.xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"));
        assertThat(elements).hasSize(2);

        WebElement element = webDriver.findElement(By.xpath("//a[text()='" + samlIdentityProviderDefinition1.getLinkText() + "']"));
        assertThat(element).isNotNull();
        element = webDriver.findElement(By.xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"));
        element.click();
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        sendCredentials(testAccounts.getUserName(), testAccounts.getPassword());
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Where to?");

        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(testZone1Url + "/logout.do");

        //disable the provider
        SamlLogoutAuthSourceEndpoint.logoutAuthSource_goesToSamlWelcomePage(webDriver, SIMPLESAMLPHP_UAA_ACCEPTANCE, SAML_AUTH_SOURCE);
        provider.setActive(false);
        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertThat(provider.getId()).isNotNull();
        webDriver.get(testZone1Url + "/login");
        assertThat(webDriver.getTitle()).isEqualTo(zone.getName());
        elements = webDriver.findElements(By.xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"));
        assertThat(elements).hasSize(1);

        //enable the provider
        provider.setActive(true);
        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertThat(provider.getId()).isNotNull();
        webDriver.get(testZone1Url + "/login");
        assertThat(webDriver.getTitle()).isEqualTo(zone.getName());
        elements = webDriver.findElements(By.xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"));
        assertThat(elements).hasSize(2);
    }

    @Test
    void loginPageShowsIDPsForAuthcodeClient() throws Exception {
        IdentityProvider<SamlIdentityProviderDefinition> provider = createIdentityProvider(SAML_ORIGIN);
        IdentityProvider<SamlIdentityProviderDefinition> provider2 = createIdentityProvider("simplesamlphp2");
        List<String> idps = Arrays.asList(
                provider.getConfig().getIdpEntityAlias(),
                provider2.getConfig().getIdpEntityAlias()
        );

        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");

        String clientId = UUID.randomUUID().toString();
        UaaClientDetails clientDetails = new UaaClientDetails(clientId, null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.none", "http://localhost:8080/login");
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);

        testClient.createClient(adminAccessToken, clientDetails);

        webDriver.get(baseUrl + "/oauth/authorize?client_id=" + clientId + "&redirect_uri=http%3A%2F%2Flocalhost%3A8888%2Flogin&response_type=code&state=8tp0tR");
        webDriver.findElement(By.xpath("//a[text()='" + provider.getConfig().getLinkText() + "']"));
        webDriver.findElement(By.xpath("//a[text()='" + provider2.getConfig().getLinkText() + "']"));
    }

    @Test
    void loginSamlOnlyProviderNoUsernamePassword() throws Exception {
        IdentityProvider provider = createIdentityProvider(SAML_ORIGIN);
        IdentityProvider provider2 = createIdentityProvider("simplesamlphp2");
        List<String> idps = Arrays.asList(provider.getOriginKey(), provider2.getOriginKey());
        webDriver.get(baseUrl + "/logout.do");
        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");

        String clientId = UUID.randomUUID().toString();
        UaaClientDetails clientDetails = new UaaClientDetails(clientId, null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.none", "http://localhost:8080/uaa/login");
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);
        testClient.createClient(adminAccessToken, clientDetails);
        webDriver.get(baseUrl + "/oauth/authorize?client_id=" + clientId + "&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fuaa%3Alogin&response_type=code&state=8tp0tR");
        try {
            webDriver.findElement(By.name("username"));
            fail("Element username should not be present");
        } catch (NoSuchElementException ignored) {
        }
        try {
            webDriver.findElement(By.name("password"));
            fail("Element username should not be present");
        } catch (NoSuchElementException ignored) {
        }
        webDriver.get(baseUrl + "/logout.do");
    }

    @Test
    @Disabled("SAML test fails: Requires logout and AutomaticRedirect")
    void samlLoginClientIDPAuthorizationAutomaticRedirect() throws Exception {
        webDriver.get(baseUrl + "/logout.do");
        IdentityProvider<SamlIdentityProviderDefinition> provider = createIdentityProvider(SAML_ORIGIN);
        assertThat(provider.getConfig().getIdpEntityAlias()).isEqualTo(provider.getOriginKey());
        List<String> idps = Collections.singletonList(provider.getOriginKey());
        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");

        String clientId = UUID.randomUUID().toString();
        UaaClientDetails clientDetails = new UaaClientDetails(clientId, null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.none", baseUrl);
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);
        clientDetails.setAutoApproveScopes(Collections.singleton("true"));

        testClient.createClient(adminAccessToken, clientDetails);

        webDriver.get("%s/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&state=8tp0tR".formatted(baseUrl, clientId, URLEncoder.encode(baseUrl, StandardCharsets.UTF_8)));
        // we should now be in the Simple SAML PHP site
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        sendCredentials(testAccounts.getUserName(), "koala");

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Where to?");
        webDriver.get(baseUrl + "/logout.do");
    }

    @Test
    void loginClientIDPAuthorizationAlreadyLoggedIn() {
        webDriver.get(baseUrl + "/logout.do");
        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");

        String clientId = UUID.randomUUID().toString();
        UaaClientDetails clientDetails = new UaaClientDetails(clientId, null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.none", "http://localhost:8080/login");
        clientDetails.setClientSecret("secret");
        List<String> idps = Collections.singletonList("okta-local"); //not authorized for the current IDP
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);

        testClient.createClient(adminAccessToken, clientDetails);

        sendCredentials(testAccounts.getUserName(), "koala", By.xpath("//input[@value='Sign in']"));

        webDriver.get(baseUrl + "/oauth/authorize?client_id=" + clientId + "&redirect_uri=http%3A%2F%2Flocalhost%3A8888%2Flogin&response_type=code&state=8tp0tR");

        assertThat(webDriver.findElement(By.cssSelector("p")).getText()).contains(clientId + " does not support your identity provider. To log into an identity provider supported by the application");
        webDriver.get(baseUrl + "/logout.do");
    }

    @Test
    @Disabled("SAML test fails: Requires logout")
    void springSamlEndpointsWithEmptyContext() throws IOException {
        CallEmptyPageAndCheckHttpStatusCode("/saml/discovery", 200);
        CallEmptyPageAndCheckHttpStatusCode("/saml/SingleLogout", 400);
        CallEmptyPageAndCheckHttpStatusCode("/saml/login/alias/foo", 400);
        CallEmptyPageAndCheckHttpStatusCode("/saml/web/metadata/login", 404);
        CallEmptyPageAndCheckHttpStatusCode("/saml/SSO/foo", 200);
    }

    public SamlIdentityProviderDefinition createTestZone2IDP(String alias) {
        return createSimplePHPSamlIDP(alias, "testzone2");
    }

    public SamlIdentityProviderDefinition createTestZone1IDP(String alias) {
        return createSimplePHPSamlIDP(alias, "testzone1");
    }

    public SamlIdentityProviderDefinition createTestZoneIDP(String alias, String zoneSubdomain) {
        return createSimplePHPSamlIDP(alias, zoneSubdomain);
    }

    private static String loadResouceAsString(String resourceLocation) {
        ResourceLoader resourceLoader = new DefaultResourceLoader();
        Resource resource = resourceLoader.getResource(resourceLocation);

        try (Reader reader = new InputStreamReader(resource.getInputStream(), UTF_8)) {
            return FileCopyUtils.copyToString(reader);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private SamlIdentityProviderDefinition createIDPWithNoSLOSConfigured() {
        String metadata = loadResouceAsString("no_single_logout_service-metadata.xml");

        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
        def.setZoneId("uaa");
        def.setMetaDataLocation(metadata);
        def.setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        def.setAssertionConsumerIndex(0);
        def.setMetadataTrustCheck(false);
        def.setShowSamlLink(true);
        def.setIdpEntityAlias("simplesamlphp");
        def.setLinkText("Login with Simple SAML PHP(simplesamlphp)");
        return def;
    }

    private void sendCredentials(String username, String password, By loginButtonSelector) {
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.findElement(By.name("password")).sendKeys(password);
        webDriver.findElement(loginButtonSelector).click();
    }

    private void sendCredentials(String username, String password) {
        sendCredentials(username, password, By.id("submit_button"));
    }

    private void CallEmptyPageAndCheckHttpStatusCode(String errorPath, int codeExpected) throws IOException {
        HttpURLConnection cn = (HttpURLConnection) new URL(baseUrl + errorPath).openConnection();
        cn.setRequestMethod("GET");
        cn.connect();
        assertThat(codeExpected).as("Check status code from " + errorPath + " is " + codeExpected).isEqualTo(cn.getResponseCode());
    }
}
