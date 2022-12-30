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
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.integration.util.ScreenshotOnFail;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.RetryRule;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.flywaydb.core.internal.util.StringUtils;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.xml.ConfigurationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.cloudfoundry.identity.uaa.authentication.AbstractClientParametersAuthenticationFilter.CLIENT_SECRET;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.createSimplePHPSamlIDP;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.assertSupportsZoneDNS;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.getZoneAdminToken;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.isMember;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ATTRIBUTES;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.EMAIL_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_ATTRIBUTE_PREFIX;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.GRANT_TYPE;
import static org.springframework.test.context.TestExecutionListeners.MergeMode.MERGE_WITH_DEFAULTS;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
@TestExecutionListeners(value = { ScreenshotOnFail.class }, mergeMode = MERGE_WITH_DEFAULTS)
public class SamlLoginIT {

    private static final String SAML_ORIGIN = "simplesamlphp";
    @Autowired @Rule
    public IntegrationTestRule integrationTestRule;

    @Rule
    public RetryRule retryRule = new RetryRule(3);

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
    private static SamlTestUtils samlTestUtils;

    @BeforeClass
    public static void setupSamlUtils() {
        assertSupportsZoneDNS();
        samlTestUtils = new SamlTestUtils();
        try {
            samlTestUtils.initialize();
        } catch (ConfigurationException e) {
            samlTestUtils.initializeSimple();
        }
    }

    @Before
    public void setup() {
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

    @After
    public void cleanup() {
        String token = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");
        for (String zoneId : Arrays.asList("testzone1", "testzone2", "testzone3", "testzone4", "uaa")) {
            String groupId = IntegrationTestUtils.getGroup(token, "", baseUrl, String.format("zones.%s.admin", zoneId)).getId();
            IntegrationTestUtils.deleteGroup(token, "", baseUrl, groupId);

            try {
                IntegrationTestUtils.deleteZone(baseUrl, zoneId, token);
                IntegrationTestUtils.deleteProvider(token, baseUrl, "uaa", zoneId + ".cloudfoundry-saml-login");
            } catch(Exception ignored){}
        }
    }

    public static String getValidRandomIDPMetaData() {
        return String.format(MockMvcUtils.IDP_META_DATA, new RandomValueStringGenerator().generate());
    }

    @Before
    public void clearWebDriverOfCookies() {
        for (String domain : Arrays.asList("localhost", "testzone1.localhost", "testzone2.localhost", "testzone3.localhost", "testzone4.localhost")) {
            webDriver.get(baseUrl.replace("localhost", domain) + "/logout.do");
            webDriver.manage().deleteAllCookies();
        }
        webDriver.get(IntegrationTestUtils.SIMPLESAMLPHP_UAA_ACCEPTANCE + "/module.php/core/authenticate.php?as=example-userpass&logout");
    }

    @Test
    public void testContentTypes() {
        String loginUrl = baseUrl + "/login";
        HttpHeaders jsonHeaders = new HttpHeaders();
        jsonHeaders.add("Accept", "application/json");
        ResponseEntity<Map> jsonResponseEntity = restOperations.exchange(loginUrl,
            HttpMethod.GET,
            new HttpEntity<>(jsonHeaders),
            Map.class);
        assertThat(jsonResponseEntity.getHeaders().get("Content-Type").get(0), containsString(APPLICATION_JSON_VALUE));

        HttpHeaders htmlHeaders = new HttpHeaders();
        htmlHeaders.add("Accept", "text/html");
        ResponseEntity<Void> htmlResponseEntity = restOperations.exchange(loginUrl,
            HttpMethod.GET,
            new HttpEntity<>(htmlHeaders),
            Void.class);
        assertThat(htmlResponseEntity.getHeaders().get("Content-Type").get(0), containsString(TEXT_HTML_VALUE));

        HttpHeaders defaultHeaders = new HttpHeaders();
        defaultHeaders.add("Accept", "*/*");
        ResponseEntity<Void> defaultResponseEntity = restOperations.exchange(loginUrl,
            HttpMethod.GET,
            new HttpEntity<>(defaultHeaders),
            Void.class);
        assertThat(defaultResponseEntity.getHeaders().get("Content-Type").get(0), containsString(TEXT_HTML_VALUE));
    }

    @Test
    public void testSimpleSamlPhpPasscodeRedirect() throws Exception {
        testSimpleSamlLogin("/passcode", "Temporary Authentication Code");
    }

    @Test
    public void testSimpleSamlLoginWithAddShadowUserOnLoginFalse() throws Exception {
        // Deleting marissa@test.org from simplesamlphp because previous SAML authentications automatically
        // create a UAA user with the email address as the username.
        deleteUser(SAML_ORIGIN, testAccounts.getEmail());

        IdentityProvider provider = IntegrationTestUtils.createIdentityProvider(SAML_ORIGIN, false, baseUrl, serverRunning);
        String clientId = "app-addnew-false"+ new RandomValueStringGenerator().generate();
        String redirectUri = "http://nosuchhostname:0/nosuchendpoint";
        BaseClientDetails client = createClientAndSpecifyProvider(clientId, provider, redirectUri);

        String firstUrl = "/oauth/authorize?"
                + "client_id=" + clientId
                + "&response_type=code"
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);

        webDriver.get(baseUrl + firstUrl);
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(testAccounts.getPassword());
        webDriver.findElement(By.xpath("//input[@value='Login']")).click();

        assertThat(webDriver.getCurrentUrl(), containsString(redirectUri + "?error=access_denied&error_description=SAML+user+does+not+exist.+You+can+correct+this+by+creating+a+shadow+user+for+the+SAML+user."));
    }

    @Test
    public void incorrectResponseFromSamlIDP_showErrorFromSaml() {
        String zoneId = "testzone3";
        String zoneUrl = baseUrl.replace("localhost",zoneId+".localhost");

        //identity client token
        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );
        //create the zone
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId, new IdentityZoneConfiguration());

        //create a zone admin user
        String email = new RandomValueStringGenerator().generate() +"@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl,email ,"firstname", "lastname", email, true);
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

        webDriver.get(zoneUrl);
        webDriver.findElement(By.linkText("Login with Simple SAML PHP(simplesamlphp)")).click();
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(testAccounts.getPassword());
        webDriver.findElement(By.xpath("//input[@value='Login']")).click();

        assertEquals("No local entity found for alias invalid, verify your configuration.", webDriver.findElement(By.cssSelector("h2")).getText());
    }

    @Test
    //Ensure this runs
    public void testSimpleSamlPhpLogin() throws Exception {
        Long beforeTest = System.currentTimeMillis();
        testSimpleSamlLogin("/login", "You should not see this page. Set up your redirect URI.");
        Long afterTest = System.currentTimeMillis();
        String zoneAdminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "admin", "adminsecret");
        ScimUser user = IntegrationTestUtils.getUser(zoneAdminToken, baseUrl, SAML_ORIGIN, testAccounts.getEmail());
        IntegrationTestUtils.validateUserLastLogon(user, beforeTest, afterTest);
    }

    @Test
    public void testSimpleSamlPhpLoginDisplaysLastLogin() throws Exception {
        Long beforeTest = System.currentTimeMillis();
        IdentityProvider<SamlIdentityProviderDefinition> provider = createIdentityProvider(SAML_ORIGIN);
        login(provider);
        logout();
        login(provider);

        assertNotNull(webDriver.findElement(By.cssSelector("#last_login_time")));
        Long afterTest = System.currentTimeMillis();
        String zoneAdminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "admin", "adminsecret");
        ScimUser user = IntegrationTestUtils.getUser(zoneAdminToken, baseUrl, SAML_ORIGIN, testAccounts.getEmail());
        IntegrationTestUtils.validateUserLastLogon(user, beforeTest, afterTest);
    }

    @Test
    public void testSingleLogout() throws Exception {
        IdentityProvider<SamlIdentityProviderDefinition> provider = createIdentityProvider(SAML_ORIGIN);

        webDriver.get(baseUrl + "/login");
        Assert.assertEquals("Predix", webDriver.getTitle());
        webDriver.findElement(By.xpath("//a[text()='" + provider.getConfig().getLinkText() + "']")).click();
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(testAccounts.getPassword());
        webDriver.findElement(By.xpath("//input[@value='Login']")).click();
        //This is modified for branding login.yml changes...
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("You should not see this page. Set up your redirect URI."));

        //Predix branded UAA does not have the elements referenced below on the home page...
        /*
        webDriver.findElement(By.cssSelector(".dropdown-trigger")).click();
        webDriver.findElement(By.linkText("Sign Out")).click();
        logout();
        IntegrationTestUtils.validateAccountChooserCookie(baseUrl, webDriver, IdentityZoneHolder.get());
        webDriver.findElement(By.xpath("//a[text()='" + provider.getConfig().getLinkText() + "']")).click();

        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        */
    }

    @Test
    public void testSingleLogoutWithLogoutRedirect() {
        String zoneId = "testzone2";
        String zoneUrl = baseUrl.replace("localhost",zoneId+".localhost");

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
        //create the zone
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId, config);


        //create a zone admin user
        String email = new RandomValueStringGenerator().generate() +"@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl,email ,"firstname", "lastname", email, true);
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
        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);

        webDriver.get(zoneUrl + "/login");
        Assert.assertTrue(webDriver.getTitle().contains("testzone2"));
        webDriver.findElement(By.xpath("//a[text()='" + provider.getConfig().getLinkText() + "']")).click();
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(testAccounts.getPassword());
        webDriver.findElement(By.xpath("//input[@value='Login']")).click();
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("You should not see this page. Set up your redirect URI."));

        //Predix branded UAA does not have the elements/links referenced below on the home page...
        /*
        String redirectUrl = zoneUrl + "/login?test=test";
        BaseClientDetails clientDetails = new BaseClientDetails("test-logout-redirect", null, null, "authorization_code", null);
        clientDetails.setRegisteredRedirectUri(Collections.singleton(redirectUrl));
        clientDetails.setClientSecret("secret");
        IntegrationTestUtils.createOrUpdateClient(zoneAdminToken, baseUrl, zoneId, clientDetails);

        webDriver.get(zoneUrl + "/logout.do?redirect=" + URLEncoder.encode(redirectUrl, StandardCharsets.UTF_8) + "&client_id=test-logout-redirect");
        assertEquals(redirectUrl, webDriver.getCurrentUrl());
        */    
    }

    @Test
    public void testSingleLogoutWithNoLogoutUrlOnIDP() throws Exception {
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

        webDriver.get(baseUrl + "/login");
        //This is modified for branding login.yml changes...
        Assert.assertEquals("Predix", webDriver.getTitle());
        webDriver.findElement(By.xpath("//a[text()='" + provider.getConfig().getLinkText() + "']")).click();
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(testAccounts.getPassword());
        webDriver.findElement(By.xpath("//input[@value='Login']")).click();
        //This is modified for branding login.yml changes...
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("You should not see this page. Set up your redirect URI."));

        //Predix branded UAA does not have the elements referenced below on the home page...
        /*
        webDriver.findElement(By.cssSelector(".dropdown-trigger")).click();
        webDriver.findElement(By.linkText("Sign Out")).click();
        webDriver.findElement(By.xpath("//a[text()='" + provider.getConfig().getLinkText() + "']")).click();
        //This is modified for branding login.yml changes...
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("You should not see this page. Set up your redirect URI."));
        */
    }

    @Test
    public void testGroupIntegration() throws Exception {
        //This is modified for branding login.yml changes...
        testSimpleSamlLogin("/login", "You should not see this page. Set up your redirect URI.", "marissa4", "saml2");
    }

    @Test
    public void testFavicon_Should_Not_Save() throws Exception {
        webDriver.get(baseUrl + "/favicon.ico");
        //This is modified for branding login.yml changes...
        testSimpleSamlLogin("/login", "You should not see this page. Set up your redirect URI.", "marissa4", "saml2");
    }


    private void testSimpleSamlLogin(String firstUrl, String lookfor) throws Exception {
        testSimpleSamlLogin(firstUrl, lookfor, testAccounts.getUserName(), testAccounts.getPassword());
    }
    private void testSimpleSamlLogin(String firstUrl, String lookfor, String username, String password) throws Exception {
        IdentityProvider<SamlIdentityProviderDefinition> provider = createIdentityProvider(SAML_ORIGIN);

        webDriver.get(baseUrl + firstUrl);
        //Assert.assertEquals("Cloud Foundry", webDriver.getTitle());
        webDriver.findElement(By.xpath("//a[text()='" + provider.getConfig().getLinkText() + "']")).click();
        //takeScreenShot();
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.findElement(By.name("password")).sendKeys(password);
        webDriver.findElement(By.xpath("//input[@value='Login']")).click();
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString(lookfor));
        IntegrationTestUtils.validateAccountChooserCookie(baseUrl, webDriver, IdentityZoneHolder.get());
    }

    protected IdentityProvider<SamlIdentityProviderDefinition> createIdentityProvider(String originKey) throws Exception {
        return IntegrationTestUtils.createIdentityProvider(originKey, true, baseUrl, serverRunning);
    }

    protected BaseClientDetails createClientAndSpecifyProvider(String clientId, IdentityProvider provider,
            String redirectUri) {

        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "identity", "identitysecret")
        );
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );
        String email = new RandomValueStringGenerator().generate() +"@samltesting.org";
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

        BaseClientDetails clientDetails =
                new BaseClientDetails(clientId, null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource", redirectUri);
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
    public void test_SamlInvitation_Automatic_Redirect_In_Zone2() throws Exception {
        perform_SamlInvitation_Automatic_Redirect_In_Zone2("marissa2", "saml2", true);
        perform_SamlInvitation_Automatic_Redirect_In_Zone2("marissa2", "saml2", true);
        perform_SamlInvitation_Automatic_Redirect_In_Zone2("marissa2", "saml2", true);

        perform_SamlInvitation_Automatic_Redirect_In_Zone2("marissa3", "saml2", false);
        perform_SamlInvitation_Automatic_Redirect_In_Zone2("marissa3", "saml2", false);
        perform_SamlInvitation_Automatic_Redirect_In_Zone2("marissa3", "saml2", false);
    }

    public void perform_SamlInvitation_Automatic_Redirect_In_Zone2(String username, String password, boolean emptyList) {
        //ensure we are able to resolve DNS for hostname testzone1.localhost
        String zoneId = "testzone2";
        String zoneUrl = baseUrl.replace("localhost",zoneId+".localhost");

        //identity client token
        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
        //admin client token - to create users
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );
        //create the zone

        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId, null);

        //create a zone admin user
        String email = new RandomValueStringGenerator().generate() +"@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl,email ,"firstname", "lastname", email, true);
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

        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken,baseUrl,provider);
        assertEquals(provider.getOriginKey(), provider.getConfig().getIdpEntityAlias());

        UaaIdentityProviderDefinition uaaDefinition = new UaaIdentityProviderDefinition(
            new PasswordPolicy(1,255,0,0,0,0,12),
            new LockoutPolicy(10, 10, 10)
        );
        uaaDefinition.setEmailDomain(emptyList ? Collections.EMPTY_LIST : Arrays.asList("*.*","*.*.*"));
        IdentityProvider<UaaIdentityProviderDefinition> uaaProvider = IntegrationTestUtils.getProvider(zoneAdminToken, baseUrl, zoneId, OriginKeys.UAA);
        uaaProvider.setConfig(uaaDefinition);
        uaaProvider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken,baseUrl,uaaProvider);

        BaseClientDetails uaaAdmin = new BaseClientDetails("admin","","", "client_credentials","uaa.admin,scim.read,scim.write");
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
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.findElement(By.name("password")).sendKeys(password);
        webDriver.findElement(By.xpath("//input[@value='Login']")).click();

        //we should now be on the login page because we don't have a redirect
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("You should not see this page. Set up your redirect URI."));

        uaaProvider.setConfig((UaaIdentityProviderDefinition) uaaDefinition.setEmailDomain(null));
        IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken,baseUrl,uaaProvider);

        String acceptedUserId = IntegrationTestUtils.getUserId(uaaAdminToken, zoneUrl, samlIdentityProviderDefinition.getIdpEntityAlias(), useremail);
        if (StringUtils.hasText(existingUserId)) {
            assertEquals(acceptedUserId, existingUserId);
        } else {
            assertEquals(invitedUserId, acceptedUserId);
        }

        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(zoneUrl + "/logout.do");
        webDriver.get(IntegrationTestUtils.SIMPLESAMLPHP_UAA_ACCEPTANCE + "/module.php/core/authenticate.php?as=example-userpass&logout");
    }

    @Test
    public void test_RelayState_redirect_from_idp() {
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

        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId, null);

        //create a zone admin user
        String email = new RandomValueStringGenerator().generate() +"@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl,email ,"firstname", "lastname", email, true);
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

        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken,baseUrl,provider);
        assertEquals(provider.getOriginKey(), provider.getConfig().getIdpEntityAlias());

        String zoneUrl = baseUrl.replace("localhost", "testzone1.localhost");

        webDriver.get(zoneUrl + "/logout.do");

        String samlUrl = IntegrationTestUtils.SIMPLESAMLPHP_UAA_ACCEPTANCE + "/saml2/idp/SSOService.php?"+
            "spentityid=testzone1.cloudfoundry-saml-login&" +
            "RelayState=https://www.google.com";
        webDriver.get(samlUrl);
        //we should now be in the Simple SAML PHP site
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys("koala");
        webDriver.findElement(By.xpath("//input[@value='Login']")).click();

        assertThat(webDriver.getCurrentUrl(), startsWith("https://www.google.com"));
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(zoneUrl + "/logout.do");
    }

    @Test
    public void testSamlLoginClientIDPAuthorizationAutomaticRedirectInZone1() {
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

        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId, null);

        //create a zone admin user
        String email = new RandomValueStringGenerator().generate() +"@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl,email ,"firstname", "lastname", email, true);
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

        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken,baseUrl,provider);
        assertEquals(provider.getOriginKey(), provider.getConfig().getIdpEntityAlias());

        List<String> idps = Collections.singletonList(provider.getOriginKey());
        String clientId = UUID.randomUUID().toString();
        String zoneUrl = baseUrl.replace("localhost", "testzone1.localhost");
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.none", zoneUrl);
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);
        clientDetails.setAutoApproveScopes(Collections.singleton("true"));
        clientDetails = IntegrationTestUtils.createClientAsZoneAdmin(zoneAdminToken, baseUrl, zoneId, clientDetails);

        webDriver.get(zoneUrl + "/logout.do");

        String authUrl = zoneUrl + "/oauth/authorize?client_id=" + clientId + "&redirect_uri=" + URLEncoder.encode(zoneUrl) + "&response_type=code&state=8tp0tR";
        webDriver.get(authUrl);
        //we should now be in the Simple SAML PHP site
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys("koala");
        webDriver.findElement(By.xpath("//input[@value='Login']")).click();
        //This is modified for branding login.yml changes...
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("You should not see this page. Set up your redirect URI."));
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(zoneUrl + "/logout.do");
    }


    @Test
    public void testSamlLogin_Map_Groups_In_Zone1() {
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

        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId, null);

        //create a zone admin user
        String email = new RandomValueStringGenerator().generate() +"@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl,email ,"firstname", "lastname", email, true);
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

        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken,baseUrl,provider);
        assertEquals(provider.getOriginKey(), provider.getConfig().getIdpEntityAlias());

        List<String> idps = Collections.singletonList(provider.getOriginKey());

        String adminClientInZone = new RandomValueStringGenerator().generate();
        BaseClientDetails clientDetails = new BaseClientDetails(adminClientInZone, null, "openid", "authorization_code,client_credentials", "uaa.admin,scim.read,scim.write", zoneUrl);
        clientDetails.setClientSecret("secret");
        clientDetails.setAutoApproveScopes(Collections.singleton("true"));
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);

        clientDetails = IntegrationTestUtils.createClientAsZoneAdmin(zoneAdminToken, baseUrl, zoneId, clientDetails);
        String adminTokenInZone = IntegrationTestUtils.getClientCredentialsToken(zoneUrl,clientDetails.getClientId(), "secret");


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

        String authUrl = zoneUrl + "/oauth/authorize?client_id=" + clientDetails.getClientId() + "&redirect_uri=" + URLEncoder.encode(zoneUrl) + "&response_type=code&state=8tp0tR";
        webDriver.get(authUrl);
        //we should now be in the Simple SAML PHP site
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys("marissa4");
        webDriver.findElement(By.name("password")).sendKeys("saml2");
        webDriver.findElement(By.xpath("//input[@value='Login']")).click();
        //This is modified for branding login.yml changes...
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("You should not see this page. Set up your redirect URI."));
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(zoneUrl + "/logout.do");

        //validate that the groups were mapped
        String samlUserId = IntegrationTestUtils.getUserId(adminTokenInZone, zoneUrl, provider.getOriginKey(), "marissa4@test.org");
        uaaSamlUserGroup = IntegrationTestUtils.getGroup(adminTokenInZone, null, zoneUrl, "uaa.saml.user");
        uaaSamlAdminGroup = IntegrationTestUtils.getGroup(adminTokenInZone, null, zoneUrl, "uaa.saml.admin");
        assertTrue(isMember(samlUserId, uaaSamlUserGroup));
        assertTrue(isMember(samlUserId, uaaSamlAdminGroup));

    }

    @Test
    public void testSamlLogin_Custom_User_Attributes_In_ID_Token() throws Exception {

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

        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId, null);

        //create a zone admin user
        String email = new RandomValueStringGenerator().generate() +"@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl,email ,"firstname", "lastname", email, true);
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
        samlIdentityProviderDefinition.setStoreCustomAttributes(true);
        samlIdentityProviderDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX+COST_CENTERS, COST_CENTER);
        samlIdentityProviderDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX+MANAGERS, MANAGER);

        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider();
        provider.setIdentityZoneId(zoneId);
        provider.setType(OriginKeys.SAML);
        provider.setActive(true);
        provider.setConfig(samlIdentityProviderDefinition);
        provider.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        provider.setName("simplesamlphp for testzone1");

        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken,baseUrl,provider);
        assertEquals(provider.getOriginKey(), provider.getConfig().getIdpEntityAlias());

        List<String> idps = Collections.singletonList(provider.getOriginKey());

        String adminClientInZone = new RandomValueStringGenerator().generate();
        BaseClientDetails clientDetails = new BaseClientDetails(adminClientInZone, null, "openid,user_attributes", "authorization_code,client_credentials", "uaa.admin,scim.read,scim.write,uaa.resource", zoneUrl);
        clientDetails.setClientSecret("secret");
        clientDetails.setAutoApproveScopes(Collections.singleton("true"));
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);

        clientDetails = IntegrationTestUtils.createClientAsZoneAdmin(zoneAdminToken, baseUrl, zoneId, clientDetails);
        clientDetails.setClientSecret("secret");

        String adminTokenInZone = IntegrationTestUtils.getClientCredentialsToken(zoneUrl,clientDetails.getClientId(), "secret");

        webDriver.get(zoneUrl + "/logout.do");

        String authUrl = zoneUrl + "/oauth/authorize?client_id=" + clientDetails.getClientId() + "&redirect_uri=" + URLEncoder.encode(zoneUrl) + "&response_type=code&state=8tp0tR";
        webDriver.get(authUrl);
        //we should now be in the Simple SAML PHP site
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys("marissa5");
        webDriver.findElement(By.name("password")).sendKeys("saml5");
        webDriver.findElement(By.xpath("//input[@value='Login']")).click();
        //This is modified for branding login.yml changes...
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("You should not see this page. Set up your redirect URI."));

        Cookie cookie= webDriver.manage().getCookieNamed("JSESSIONID");

        //do an auth code grant
        //pass up the jsessionid
        System.out.println("cookie = " + String.format("%s=%s",cookie.getName(), cookie.getValue()));

        serverRunning.setHostName("testzone1.localhost");
        Map<String,String> authCodeTokenResponse = IntegrationTestUtils.getAuthorizationCodeTokenMap(serverRunning,
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
        assertNotNull(idToken);

        Jwt idTokenClaims = JwtHelper.decode(idToken);
        Map<String, Object> claims = JsonUtils.readValue(idTokenClaims.getClaims(), new TypeReference<Map<String, Object>>() {
        });

        assertNotNull(claims.get(USER_ATTRIBUTES));
        Map<String,List<String>> userAttributes = (Map<String, List<String>>) claims.get(USER_ATTRIBUTES);
        assertThat(userAttributes.get(COST_CENTERS), containsInAnyOrder(DENVER_CO));
        assertThat(userAttributes.get(MANAGERS), containsInAnyOrder(JOHN_THE_SLOTH, KARI_THE_ANT_EATER));

        assertNotNull("id_token should contain ACR claim", claims.get(ClaimConstants.ACR));
        Map<String,Object> acr = (Map<String, Object>) claims.get(ClaimConstants.ACR);
        assertNotNull("acr claim should contain values attribute", acr.get("values"));
        assertThat((List<String>) acr.get("values"), containsInAnyOrder(AuthnContext.PASSWORD_AUTHN_CTX));

        UserInfoResponse userInfo = IntegrationTestUtils.getUserInfo(zoneUrl, authCodeTokenResponse.get("access_token"));

        Map<String,List<String>> userAttributeMap = userInfo.getUserAttributes();
        List<String> costCenterData = userAttributeMap.get(COST_CENTERS);
        List<String> managerData = userAttributeMap.get(MANAGERS);
        assertThat(costCenterData, containsInAnyOrder(DENVER_CO));
        assertThat(managerData, containsInAnyOrder(JOHN_THE_SLOTH, KARI_THE_ANT_EATER));

    }

    @Test
    public void two_zone_saml_bearer_grant_url_metadata() throws Exception {
        Map<String, Object> claims = two_zone_saml_bearer_grant(true, "testzone4");
        String samlClientId = (String)claims.get(ClaimConstants.CLIENT_ID);
        ArrayList<String> auds = (ArrayList<String>)claims.get(ClaimConstants.AUD);
        Assert.assertTrue("aud claim must contain own client id: " + samlClientId, auds.contains(samlClientId));
    }

    @Test
    public void two_zone_saml_bearer_grant_xml_metadata() throws Exception {
        assertNotNull(two_zone_saml_bearer_grant(false, "testzone3"));
    }

    public Map<String, Object> two_zone_saml_bearer_grant(boolean urlMetadata, String zoneName) throws Exception {
        //ensure we are able to resolve DNS for hostname testzone1.localhost
        String zoneUrl = baseUrl.replace("localhost", zoneName +".localhost");


        //identity client token
        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );

        String adminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "admin", "adminsecret");

        //create the zone

        IdentityZone zone = IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl,
                zoneName,
                zoneName, null);

        String idpMetadataUrl = zoneUrl + "/saml/idp/metadata";

        String idpMetadata = urlMetadata ? idpMetadataUrl : new RestTemplate().getForObject(idpMetadataUrl, String.class);

        String idpOrigin = zone.getSubdomain() + ".cloudfoundry-saml-login";

        String uaaZoneId = IdentityZone.getUaaZoneId();
        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition()
            .setZoneId(uaaZoneId)
            .setMetaDataLocation(idpMetadata)
            .setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
            .setAssertionConsumerIndex(0)
            .setMetadataTrustCheck(false)
            .setShowSamlLink(false)
            .setIdpEntityAlias(idpOrigin);

        IdentityProvider provider = new IdentityProvider();
        provider.setConfig(def);
        provider.setActive(true);
        provider.setIdentityZoneId(uaaZoneId);
        provider.setName(idpOrigin);
        provider.setOriginKey(idpOrigin);

        IntegrationTestUtils.createOrUpdateProvider(adminToken, baseUrl, provider);

        String clientId = new RandomValueStringGenerator().generate().toLowerCase();
        String username = "saml2bearerUser";
        BaseClientDetails saml2BearerClient = new BaseClientDetails(clientId,
                                                                    null,
                                                                    "openid",
                                                                    GRANT_TYPE_SAML2_BEARER,
                                                                    "uaa.resource",
                                                                    null);
        saml2BearerClient.setAutoApproveScopes(Collections.singletonList("true"));
        saml2BearerClient.setClientSecret("secret");
        saml2BearerClient = IntegrationTestUtils.createClient(adminToken, baseUrl, saml2BearerClient);


        String audienceEntityID = "cloudfoundry-saml-login";
        String spAudienceEndpoint = baseUrl + "/oauth/token/alias/"+audienceEntityID;
        String assertion = samlTestUtils.mockAssertionEncoded(
            zone.getSubdomain()+".cloudfoundry-saml-login",
            "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            username,
            spAudienceEndpoint,
            audienceEntityID
        );

        MultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add(CLIENT_ID, saml2BearerClient.getClientId());
        postBody.add(CLIENT_SECRET, "secret");
        postBody.add(GRANT_TYPE, GRANT_TYPE_SAML2_BEARER);
        postBody.add("assertion", assertion);

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add(HttpHeaders.ACCEPT, APPLICATION_JSON_VALUE);
        headers.add(HttpHeaders.CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE);

        System.out.println("curl"+
            " -H\"Accept: application/json\""+
            " -d \"client_id="+saml2BearerClient.getClientId()+"\""+
            " -d \"client_secret=secret\""+
            " -d \"grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer\"" +
            " -d \"assertion="+assertion+"\"" +
            " " + spAudienceEndpoint+"\n\n"
        );

        ResponseEntity<String> response = new RestTemplate().exchange(new URI(spAudienceEndpoint), HttpMethod.POST, new HttpEntity<MultiValueMap>(postBody, headers), String.class);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        Map<String, Object> tokenResponse = JsonUtils.readValue(response.getBody(), new TypeReference<Map<String, Object>>() {
        });
        String jwtAccessToken = (String)tokenResponse.get("access_token");
        assertNotNull("Expecting access_token to be present in response", jwtAccessToken);
        Jwt idTokenClaims = JwtHelper.decode(jwtAccessToken);
        return JsonUtils.readValue(idTokenClaims.getClaims(), new TypeReference<Map<String, Object>>() { });
    }

    @Test
    public void testSamlLogin_Email_In_ID_Token_When_UserID_IsNotEmail() {

        //ensure we are able to resolve DNS for hostname testzone1.localhost
        String zoneId = "testzone4";
        String zoneUrl = baseUrl.replace("localhost", zoneId+".localhost");

        //identity client token
        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
        //admin client token - to create users
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );
        //create the zone

        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId, null);

        //create a zone admin user
        String email = new RandomValueStringGenerator().generate() +"@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl,email ,"firstname", "lastname", email, true);
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
        provider.setName("simplesamlphp for "+zoneId);

        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken,baseUrl,provider);
        assertEquals(provider.getOriginKey(), provider.getConfig().getIdpEntityAlias());

        List<String> idps = Collections.singletonList(provider.getOriginKey());

        String adminClientInZone = new RandomValueStringGenerator().generate();
        BaseClientDetails clientDetails = new BaseClientDetails(adminClientInZone, null, "openid,user_attributes", "authorization_code,client_credentials", "uaa.admin,scim.read,scim.write,uaa.resource", zoneUrl);
        clientDetails.setClientSecret("secret");
        clientDetails.setAutoApproveScopes(Collections.singleton("true"));
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);

        clientDetails = IntegrationTestUtils.createClientAsZoneAdmin(zoneAdminToken, baseUrl, zoneId, clientDetails);
        clientDetails.setClientSecret("secret");

        String adminTokenInZone = IntegrationTestUtils.getClientCredentialsToken(zoneUrl,clientDetails.getClientId(), "secret");

        webDriver.get(zoneUrl + "/logout.do");

        String authUrl = zoneUrl + "/oauth/authorize?client_id=" + clientDetails.getClientId() + "&redirect_uri=" + URLEncoder.encode(zoneUrl) + "&response_type=code&state=8tp0tR";
        webDriver.get(authUrl);
        //we should now be in the Simple SAML PHP site
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys("marissa6");
        webDriver.findElement(By.name("password")).sendKeys("saml6");
        webDriver.findElement(By.xpath("//input[@value='Login']")).click();
        //This is modified for branding login.yml changes...
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("You should not see this page. Set up your redirect URI."));

        Cookie cookie= webDriver.manage().getCookieNamed("JSESSIONID");

        //do an auth code grant
        //pass up the jsessionid
        System.out.println("cookie = " + String.format("%s=%s",cookie.getName(), cookie.getValue()));

        serverRunning.setHostName(zoneId+".localhost");
        Map<String,String> authCodeTokenResponse = IntegrationTestUtils.getAuthorizationCodeTokenMap(serverRunning,
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
        assertNotNull(idToken);

        Jwt idTokenClaims = JwtHelper.decode(idToken);
        Map<String, Object> claims = JsonUtils.readValue(idTokenClaims.getClaims(), new TypeReference<Map<String, Object>>() {
        });

        assertNotNull(claims.get(USER_ATTRIBUTES));
        assertEquals("marissa6", claims.get(ClaimConstants.USER_NAME));
        assertEquals("marissa6@test.org", claims.get(ClaimConstants.EMAIL));
    }


    @Test
    public void testSimpleSamlPhpLoginInTestZone1Works() {
        String zoneId = "testzone1";

        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );

        IdentityZone zone = IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId, null);
        String email = new RandomValueStringGenerator().generate() +"@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl,email ,"firstname", "lastname", email, true);
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


        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken,baseUrl,provider);

        //we have to create two providers to avoid automatic redirect
        SamlIdentityProviderDefinition samlIdentityProviderDefinition1 = samlIdentityProviderDefinition.clone();
        samlIdentityProviderDefinition1.setIdpEntityAlias(samlIdentityProviderDefinition.getIdpEntityAlias()+"-1");
        samlIdentityProviderDefinition1.setMetaDataLocation(getValidRandomIDPMetaData());
        IdentityProvider provider1 = new IdentityProvider();
        provider1.setIdentityZoneId(zoneId);
        provider1.setType(OriginKeys.SAML);
        provider1.setActive(true);
        provider1.setConfig(samlIdentityProviderDefinition1);
        provider1.setOriginKey(samlIdentityProviderDefinition1.getIdpEntityAlias());
        provider1.setName("simplesamlphp 1 for testzone1");
        provider1 = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken,baseUrl,provider1);

        assertNotNull(provider.getId());

        String testZone1Url = baseUrl.replace("localhost", zoneId+".localhost");
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(testZone1Url + "/logout.do");
        webDriver.get(testZone1Url + "/login");
        Assert.assertEquals(zone.getName(), webDriver.getTitle());

        List<WebElement> elements = webDriver.findElements(By.xpath("//a[text()='"+ samlIdentityProviderDefinition.getLinkText()+"']"));
        assertNotNull(elements);
        assertEquals(2, elements.size());

        WebElement element = webDriver.findElement(By.xpath("//a[text()='" + samlIdentityProviderDefinition1.getLinkText() + "']"));
        assertNotNull(element);
        element = webDriver.findElement(By.xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"));
        element.click();
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(testAccounts.getPassword());
        webDriver.findElement(By.xpath("//input[@value='Login']")).click();
        //This is modified for branding login.yml changes...
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("You should not see this page. Set up your redirect URI."));

        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(testZone1Url + "/logout.do");

        //disable the provider
        webDriver.get(IntegrationTestUtils.SIMPLESAMLPHP_UAA_ACCEPTANCE + "/module.php/core/authenticate.php?as=example-userpass&logout");
        provider.setActive(false);
        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken,baseUrl,provider);
        assertNotNull(provider.getId());
        webDriver.get(testZone1Url + "/login");
        Assert.assertEquals(zone.getName(), webDriver.getTitle());
        elements = webDriver.findElements(By.xpath("//a[text()='"+ samlIdentityProviderDefinition.getLinkText()+"']"));
        assertNotNull(elements);
        assertEquals(1, elements.size());

        //enable the provider
        provider.setActive(true);
        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken,baseUrl,provider);
        assertNotNull(provider.getId());
        webDriver.get(testZone1Url + "/login");
        Assert.assertEquals(zone.getName(), webDriver.getTitle());
        elements = webDriver.findElements(By.xpath("//a[text()='"+ samlIdentityProviderDefinition.getLinkText()+"']"));
        assertNotNull(elements);
        assertEquals(2, elements.size());

    }

    @Test
    public void testLoginPageShowsIDPsForAuthcodeClient() throws Exception {
        IdentityProvider<SamlIdentityProviderDefinition> provider = createIdentityProvider(SAML_ORIGIN);
        IdentityProvider<SamlIdentityProviderDefinition> provider2 = createIdentityProvider("simplesamlphp2");
        List<String> idps = Arrays.asList(
            provider.getConfig().getIdpEntityAlias(),
            provider2.getConfig().getIdpEntityAlias()
        );

        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");

        String clientId = UUID.randomUUID().toString();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.none", "http://localhost:8080/login");
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);

        testClient.createClient(adminAccessToken, clientDetails);

        webDriver.get(baseUrl + "/oauth/authorize?client_id=" + clientId + "&redirect_uri=http%3A%2F%2Flocalhost%3A8888%2Flogin&response_type=code&state=8tp0tR");
        webDriver.findElement(By.xpath("//a[text()='" + provider.getConfig().getLinkText() + "']"));
        webDriver.findElement(By.xpath("//a[text()='" + provider2.getConfig().getLinkText() + "']"));
    }

    @Test
    public void testLoginSamlOnlyProviderNoUsernamePassword() throws Exception {
        IdentityProvider provider = createIdentityProvider(SAML_ORIGIN);
        IdentityProvider provider2 = createIdentityProvider("simplesamlphp2");
        List<String> idps = Arrays.asList(provider.getOriginKey(), provider2.getOriginKey());
        webDriver.get(baseUrl + "/logout.do");
        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");

        String clientId = UUID.randomUUID().toString();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.none", "http://localhost:8080/uaa/login");
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
    public void testSamlLoginClientIDPAuthorizationAutomaticRedirect() throws Exception {
        IdentityProvider<SamlIdentityProviderDefinition> provider = createIdentityProvider(SAML_ORIGIN);
        assertEquals(provider.getOriginKey(), provider.getConfig().getIdpEntityAlias());
        List<String> idps = Collections.singletonList(provider.getOriginKey());
        webDriver.get(baseUrl + "/logout.do");
        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");

        String clientId = UUID.randomUUID().toString();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.none", baseUrl);
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);
        clientDetails.setAutoApproveScopes(Collections.singleton("true"));

        testClient.createClient(adminAccessToken, clientDetails);

        webDriver.get(baseUrl + "/oauth/authorize?client_id=" + clientId + "&redirect_uri=" + URLEncoder.encode(baseUrl) + "&response_type=code&state=8tp0tR");
        //we should now be in the Simple SAML PHP site
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys("koala");
        webDriver.findElement(By.xpath("//input[@value='Login']")).click();

        //This is modified for branding login.yml changes...
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("You should not see this page. Set up your redirect URI."));
        webDriver.get(baseUrl + "/logout.do");
    }

    @Test
    public void testLoginClientIDPAuthorizationAlreadyLoggedIn() {
        webDriver.get(baseUrl + "/logout.do");
        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");

        String clientId = UUID.randomUUID().toString();
        BaseClientDetails clientDetails = new BaseClientDetails(clientId, null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.none", "http://localhost:8080/login");
        clientDetails.setClientSecret("secret");
        List<String> idps = Collections.singletonList("okta-local"); //not authorized for the current IDP
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);

        testClient.createClient(adminAccessToken, clientDetails);

        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys("koala");
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        webDriver.get(baseUrl + "/oauth/authorize?client_id=" + clientId + "&redirect_uri=http%3A%2F%2Flocalhost%3A8888%2Flogin&response_type=code&state=8tp0tR");

        assertThat(webDriver.findElement(By.cssSelector("p")).getText(), Matchers.containsString(clientId + " does not support your identity provider. To log into an identity provider supported by the application"));
        webDriver.get(baseUrl + "/logout.do");
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
        String idpMetaData = "<?xml version=\"1.0\"?>\n" +
                "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"" + IntegrationTestUtils.SIMPLESAMLPHP_UAA_ACCEPTANCE + "/saml2/idp/metadata.php\" ID=\"pfx06ad4153-c17c-d286-194c-dec30bb92796\"><ds:Signature>\n" +
                "  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" +
                "  <ds:Reference URI=\"#pfx06ad4153-c17c-d286-194c-dec30bb92796\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>begl1WVCsXSn7iHixtWPP8d/X+k=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>BmbKqA3A0oSLcn5jImz/l5WbpVXj+8JIpT/ENWjOjSd/gcAsZm1QvYg+RxYPBk+iV2bBxD+/yAE/w0wibsHrl0u9eDhoMRUJBUSmeyuN1lYzBuoVa08PdAGtb5cGm4DMQT5Rzakb1P0hhEPPEDDHgTTxop89LUu6xx97t2Q03Khy8mXEmBmNt2NlFxJPNt0FwHqLKOHRKBOE/+BpswlBocjOQKFsI9tG3TyjFC68mM2jo0fpUQCgj5ZfhzolvS7z7c6V201d9Tqig0/mMFFJLTN8WuZPavw22AJlMjsDY9my+4R9HKhK5U53DhcTeECs9fb4gd7p5BJy4vVp7tqqOg==</ds:SignatureValue>\n" +
                "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n" +
                "  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
                "    <md:KeyDescriptor use=\"signing\">\n" +
                "      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "        <ds:X509Data>\n" +
                "          <ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate>\n" +
                "        </ds:X509Data>\n" +
                "      </ds:KeyInfo>\n" +
                "    </md:KeyDescriptor>\n" +
                "    <md:KeyDescriptor use=\"encryption\">\n" +
                "      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "        <ds:X509Data>\n" +
                "          <ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate>\n" +
                "        </ds:X509Data>\n" +
                "      </ds:KeyInfo>\n" +
                "    </md:KeyDescriptor>\n" +
                "    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n" +
                "    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"" + IntegrationTestUtils.SIMPLESAMLPHP_UAA_ACCEPTANCE + "/saml2/idp/SSOService.php\"/>\n" +
                "  </md:IDPSSODescriptor>\n" +
                "  <md:ContactPerson contactType=\"technical\">\n" +
                "    <md:GivenName>Filip</md:GivenName>\n" +
                "    <md:SurName>Hanik</md:SurName>\n" +
                "    <md:EmailAddress>fhanik@pivotal.io</md:EmailAddress>\n" +
                "  </md:ContactPerson>\n" +
                "</md:EntityDescriptor>";

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
        webDriver.get(baseUrl + "/logout.do");
    }

    private void login(IdentityProvider<SamlIdentityProviderDefinition> provider) {
        webDriver.get(baseUrl + "/login");
        Assert.assertEquals("Predix", webDriver.getTitle());
        webDriver.findElement(By.xpath("//a[text()='" + provider.getConfig().getLinkText() + "']")).click();
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(testAccounts.getPassword());
        webDriver.findElement(By.xpath("//input[@value='Login']")).click();
    }
}
