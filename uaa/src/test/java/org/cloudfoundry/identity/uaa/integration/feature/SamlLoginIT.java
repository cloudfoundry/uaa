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

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.account.UserInfoResponse;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.endpoints.LogoutDoEndpoint;
import org.cloudfoundry.identity.uaa.integration.endpoints.OauthAuthorizeEndpoint;
import org.cloudfoundry.identity.uaa.integration.endpoints.SamlLogoutAuthSourceEndpoint;
import org.cloudfoundry.identity.uaa.integration.pageObjects.*;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.integration.util.ScreenshotOnFail;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.client.test.TestAccounts;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.*;
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
import org.junit.jupiter.api.*;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.*;
import static org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken.ACCESS_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ATTRIBUTES;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.*;
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

    public static String getValidRandomIDPMetaData() {
        return MockMvcUtils.IDP_META_DATA.formatted(new RandomValueStringGenerator().generate());
    }

    @BeforeEach
    void clearWebDriverOfCookies() {
        screenShootRule.setWebDriver(webDriver);
        for (String domain : Arrays.asList("localhost", "testzone1.localhost", "testzone2.localhost", "testzone3.localhost", "testzone4.localhost")) {
            LogoutDoEndpoint.logout(webDriver, baseUrl.replace("localhost", domain));
            new Page(webDriver).clearCookies();
        }
        SamlLogoutAuthSourceEndpoint.logoutAuthSource_goesToSamlWelcomePage(webDriver, IntegrationTestUtils.SIMPLESAMLPHP_UAA_ACCEPTANCE, SAML_AUTH_SOURCE);
    }

    @Test
    void samlSPMetadata() {
        RestTemplate request = new RestTemplate();
        ResponseEntity response = request.getForEntity(
                baseUrl + "/saml/metadata", String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        String metadataXml = (String) response.getBody();

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
        String loginUrl = baseUrl + "/login";
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
    @Disabled("SAML test fails")
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

        IdentityProvider provider = IntegrationTestUtils.createIdentityProvider(SAML_ORIGIN, false, baseUrl, serverRunning);
        String clientId = "app-addnew-false" + new RandomValueStringGenerator().generate();
        String redirectUri = "http://nosuchhostname:0/nosuchendpoint";
        createClientAndSpecifyProvider(clientId, provider, redirectUri);

        OauthAuthorizeEndpoint
                .authorize_goesToSamlLoginPage(webDriver, baseUrl, redirectUri, clientId, "code")
                .login_goesToCustomErrorPage(
                        testAccounts.getUserName(),
                        testAccounts.getPassword(),
                        containsString(redirectUri + "?error=access_denied&error_description=SAML+user+does+not+exist.+You+can+correct+this+by+creating+a+shadow+user+for+the+SAML+user."));
    }

    @Test
    @Disabled("SAML test fails")
    void incorrectResponseFromSamlIDP_showErrorFromSaml() {
        String zoneId = "testzone3";
        String zoneUrl = baseUrl.replace("localhost", zoneId + ".localhost");

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
        IdentityProvider provider = new IdentityProvider();
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
    @Disabled("SAML test fails")
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
    @Disabled("SAML test fails")
    void simpleSamlPhpLoginDisplaysLastLogin() throws Exception {
        Long beforeTest = System.currentTimeMillis();
        IdentityProvider<SamlIdentityProviderDefinition> provider = createIdentityProvider(SAML_ORIGIN);
        LoginPage.go(webDriver, baseUrl)
                .clickSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .login_goesToHomePage(testAccounts.getUserName(), testAccounts.getPassword())
                .logout_goesToLoginPage()
                .clickSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .login_goesToHomePage(testAccounts.getUserName(), testAccounts.getPassword())
                .hasLastLoginTime();

        Long afterTest = System.currentTimeMillis();
        String zoneAdminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "admin", "adminsecret");
        ScimUser user = IntegrationTestUtils.getUser(zoneAdminToken, baseUrl, SAML_ORIGIN, testAccounts.getEmail());
        IntegrationTestUtils.validateUserLastLogon(user, beforeTest, afterTest);
    }

    @Test
    @Disabled("SAML test fails")
    void singleLogout() throws Exception {
        IdentityProvider<SamlIdentityProviderDefinition> provider = createIdentityProvider(SAML_ORIGIN);

        LoginPage.go(webDriver, baseUrl)
                .clickSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .login_goesToHomePage(testAccounts.getUserName(), testAccounts.getPassword())
                .logout_goesToLoginPage()
                .clickSamlLink_goesToSamlLoginPage(SAML_ORIGIN);
    }

    @Test
    @Disabled("SAML test fails")
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
        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider();
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
    @Disabled("SAML test fails")
    void singleLogoutWithNoLogoutUrlOnIDP() throws Exception {
        SamlIdentityProviderDefinition providerDefinition = createIDPWithNoSLOSConfigured();
        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider();
        provider.setIdentityZoneId(OriginKeys.UAA);
        provider.setType(OriginKeys.SAML);
        provider.setActive(true);
        provider.setConfig(providerDefinition);
        provider.setOriginKey(providerDefinition.getIdpEntityAlias());
        provider.setName("simplesamlphp for uaa");

        String zoneAdminToken = getZoneAdminToken(baseUrl, serverRunning);

        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);

        LoginPage.go(webDriver, baseUrl)
                .clickSamlLink_goesToSamlLoginPage("simplesamlphp")
                .login_goesToHomePage(testAccounts.getUserName(), testAccounts.getPassword())
                .logout_goesToLoginPage()
                .clickSamlLink_goesToHomePage();
    }

    @Test
    @Disabled("SAML test fails")
    void groupIntegration() throws Exception {
        createIdentityProvider(SAML_ORIGIN);
        LoginPage.go(webDriver, baseUrl)
                .clickSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .login_goesToHomePage(MARISSA4_USERNAME, MARISSA4_PASSWORD);
    }

    @Test
    @Disabled("SAML test fails")
    void faviconShouldNotSave() throws Exception {
        createIdentityProvider(SAML_ORIGIN);
        FaviconElement.getDefaultIcon(webDriver, baseUrl);
        LoginPage.go(webDriver, baseUrl)
                .clickSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .login_goesToHomePage(MARISSA4_USERNAME, MARISSA4_PASSWORD);
    }


    private void testSimpleSamlLogin(String firstUrl, String lookfor) throws Exception {
        testSimpleSamlLogin(firstUrl, lookfor, testAccounts.getUserName(), testAccounts.getPassword());
    }

    private void testSimpleSamlLogin(String firstUrl, String lookfor, String username, String password) throws Exception {
        IdentityProvider<SamlIdentityProviderDefinition> provider = createIdentityProvider(SAML_ORIGIN);

        webDriver.get(baseUrl + firstUrl);
        assertThat(webDriver.getTitle()).isEqualTo("Cloud Foundry");
        webDriver.findElement(By.xpath("//a[text()='" + provider.getConfig().getLinkText() + "']")).click();
        //takeScreenShot();
        assertThat(webDriver.getCurrentUrl()).contains("loginuserpass");
        sendCredentials(username, password);
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains(lookfor);
    }

    protected IdentityProvider<SamlIdentityProviderDefinition> createIdentityProvider(String originKey) throws Exception {
        return IntegrationTestUtils.createIdentityProvider(originKey, true, baseUrl, serverRunning);
    }

    protected UaaClientDetails createClientAndSpecifyProvider(String clientId, IdentityProvider provider,
                                                              String redirectUri) {

        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
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

        return clientDetails;
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
    @Disabled("SAML test fails")
    void saml_invitation_automatic_redirect_in_zone2() throws Exception {
        perform_SamlInvitation_Automatic_Redirect_In_Zone2(MARISSA2_USERNAME, MARISSA2_PASSWORD, true);
        perform_SamlInvitation_Automatic_Redirect_In_Zone2(MARISSA2_USERNAME, MARISSA2_PASSWORD, true);
        perform_SamlInvitation_Automatic_Redirect_In_Zone2(MARISSA2_USERNAME, MARISSA2_PASSWORD, true);

        perform_SamlInvitation_Automatic_Redirect_In_Zone2(MARISSA3_USERNAME, MARISSA3_PASSWORD, false);
        perform_SamlInvitation_Automatic_Redirect_In_Zone2(MARISSA3_USERNAME, MARISSA3_PASSWORD, false);
        perform_SamlInvitation_Automatic_Redirect_In_Zone2(MARISSA3_USERNAME, MARISSA3_PASSWORD, false);
    }

    public void perform_SamlInvitation_Automatic_Redirect_In_Zone2(String username, String password, boolean emptyList) {
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
        uaaDefinition.setEmailDomain(emptyList ? Collections.EMPTY_LIST : Arrays.asList("*.*", "*.*.*"));
        IdentityProvider<UaaIdentityProviderDefinition> uaaProvider = IntegrationTestUtils.getProvider(zoneAdminToken, baseUrl, zoneId, OriginKeys.UAA);
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
        SamlLogoutAuthSourceEndpoint.logoutAuthSource_goesToSamlWelcomePage(webDriver, IntegrationTestUtils.SIMPLESAMLPHP_UAA_ACCEPTANCE, SAML_AUTH_SOURCE);
    }

    @Test
    @Disabled("SAML test fails")
    void relay_state_redirect_from_idp() {
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

        String samlUrl = IntegrationTestUtils.SIMPLESAMLPHP_UAA_ACCEPTANCE + "/saml2/idp/SSOService.php?"
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
    @Disabled("SAML test fails")
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
        clientDetails = IntegrationTestUtils.createClientAsZoneAdmin(zoneAdminToken, baseUrl, zoneId, clientDetails);

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
    @Disabled("SAML test fails")
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
        assertThat(isMember(samlUserId, uaaSamlUserGroup)).isTrue();
        assertThat(isMember(samlUserId, uaaSamlAdminGroup)).isTrue();

    }

    @Test
    @Disabled("SAML test fails")
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

        String authUrl = zoneUrl + "/oauth/authorize?client_id=" + clientDetails.getClientId() + "&redirect_uri=" + URLEncoder.encode(zoneUrl, StandardCharsets.UTF_8) + "&response_type=code&state=8tp0tR";
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
        String accessToken = (String) authCodeTokenResponse.get(ACCESS_TOKEN);
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
        List<String> userInfoRoles = (List<String>) userInfo.getRoles();
        assertThat(userInfoRoles).containsExactlyInAnyOrder(expectedRoles);
    }

    @Test
    @Disabled("SAML test fails")
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

        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider();
        provider.setIdentityZoneId(zoneId);
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

        String adminTokenInZone = IntegrationTestUtils.getClientCredentialsToken(zoneUrl, clientDetails.getClientId(), "secret");

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
    @Disabled("SAML test fails")
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
        IdentityProvider provider1 = new IdentityProvider();
        provider1.setIdentityZoneId(zoneId);
        provider1.setType(OriginKeys.SAML);
        provider1.setActive(true);
        provider1.setConfig(samlIdentityProviderDefinition1);
        provider1.setOriginKey(samlIdentityProviderDefinition1.getIdpEntityAlias());
        provider1.setName("simplesamlphp 1 for testzone1");
        provider1 = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider1);

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
        SamlLogoutAuthSourceEndpoint.logoutAuthSource_goesToSamlWelcomePage(webDriver, IntegrationTestUtils.SIMPLESAMLPHP_UAA_ACCEPTANCE, SAML_AUTH_SOURCE);
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
    @Disabled("SAML test fails")
    void samlLoginClientIDPAuthorizationAutomaticRedirect() throws Exception {
        IdentityProvider<SamlIdentityProviderDefinition> provider = createIdentityProvider(SAML_ORIGIN);
        assertThat(provider.getConfig().getIdpEntityAlias()).isEqualTo(provider.getOriginKey());
        List<String> idps = Collections.singletonList(provider.getOriginKey());
        webDriver.get(baseUrl + "/logout.do");
        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");

        String clientId = UUID.randomUUID().toString();
        UaaClientDetails clientDetails = new UaaClientDetails(clientId, null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.none", baseUrl);
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);
        clientDetails.setAutoApproveScopes(Collections.singleton("true"));

        testClient.createClient(adminAccessToken, clientDetails);

        webDriver.get(baseUrl + "/oauth/authorize?client_id=" + clientId + "&redirect_uri=" + URLEncoder.encode(baseUrl, StandardCharsets.UTF_8) + "&response_type=code&state=8tp0tR");
        //we should now be in the Simple SAML PHP site
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        sendCredentials(testAccounts.getUserName(), "koala");

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Where to?");
        webDriver.get(baseUrl + "/logout.do");
    }

    @Test
    @Disabled("SAML test fails")
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
    @Disabled("SAML test fails")
    void springSamlEndpointsWithEmptyContext() throws IOException {
        CallEmpptyPageAndCheckHttpStatusCode("/saml/discovery", 200);
        CallEmpptyPageAndCheckHttpStatusCode("/saml/SingleLogout", 400);
        CallEmpptyPageAndCheckHttpStatusCode("/saml/login/alias/foo", 400);
        CallEmpptyPageAndCheckHttpStatusCode("/saml/web/metadata/login", 404);
        CallEmpptyPageAndCheckHttpStatusCode("/saml/SSO/foo", 200);
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

    private SamlIdentityProviderDefinition createIDPWithNoSLOSConfigured() {
        String idpMetaData = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                + "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"http://uaa-acceptance.cf-app.com/saml-idp\">\n"
                + "    <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n"
                + "        <md:KeyDescriptor use=\"signing\">\n"
                + "            <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n"
                + "                <ds:X509Data>\n"
                + "                    <ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate>\n"
                + "                </ds:X509Data>\n"
                + "            </ds:KeyInfo>\n"
                + "        </md:KeyDescriptor>\n"
                + "        <md:KeyDescriptor use=\"encryption\">\n"
                + "            <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n"
                + "                <ds:X509Data>\n"
                + "                    <ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate>\n"
                + "                </ds:X509Data>\n"
                + "            </ds:KeyInfo>\n"
                + "        </md:KeyDescriptor>\n"
                + "        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n"
                + "        <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"" + IntegrationTestUtils.SIMPLESAMLPHP_UAA_ACCEPTANCE + "/module.php/saml/idp/singleSignOnService\"/>\n"
                + "    </md:IDPSSODescriptor>\n"
                + "    <md:ContactPerson contactType=\"technical\">\n"
                + "        <md:GivenName>TAS Identity &amp; Credentials</md:GivenName>\n"
                + "        <md:EmailAddress>mailto:tas-identity-and-credentials@groups.vmware.com</md:EmailAddress>\n"
                + "    </md:ContactPerson>\n"
                + "</md:EntityDescriptor>\n";

        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
        def.setZoneId("uaa");
        def.setMetaDataLocation(idpMetaData);
        def.setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        def.setAssertionConsumerIndex(0);
        def.setMetadataTrustCheck(false);
        def.setShowSamlLink(true);
        def.setIdpEntityAlias("simplesamlphp");
        def.setLinkText("Login with Simple SAML PHP(simplesamlphp)");
        return def;
    }

    private void logout() {
        webDriver.findElement(By.cssSelector(".dropdown-trigger")).click();
        webDriver.findElement(By.linkText("Sign Out")).click();
    }

    private void login(IdentityProvider<SamlIdentityProviderDefinition> provider) {
        webDriver.get(baseUrl + "/login");
        assertThat(webDriver.getTitle()).isEqualTo("Cloud Foundry");
        webDriver.findElement(By.xpath("//a[text()='" + provider.getConfig().getLinkText() + "']")).click();
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        sendCredentials(testAccounts.getUserName(), testAccounts.getPassword());
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

    private void CallEmpptyPageAndCheckHttpStatusCode(String errorPath, int codeExpected) throws IOException {
        HttpURLConnection cn = (HttpURLConnection) new URL(baseUrl + errorPath).openConnection();
        cn.setRequestMethod("GET");
        cn.connect();
        assertThat(codeExpected).as("Check status code from " + errorPath + " is " + codeExpected).isEqualTo(cn.getResponseCode());
    }
}
