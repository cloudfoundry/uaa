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
import org.cloudfoundry.identity.uaa.integration.pageObjects.SamlLoginPage;
import org.cloudfoundry.identity.uaa.integration.pageObjects.SamlWelcomePage;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.integration.util.ScreenshotOnFailExtension;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.client.test.TestAccounts;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.test.UaaWebDriver;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.flywaydb.core.internal.util.StringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
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
import org.xmlunit.assertj.XmlAssert;

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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.createSimplePHPSamlIDP;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.doesSupportZoneDNS;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.getZoneAdminToken;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.isMember;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.saml.Saml2TestUtils.xmlNamespaces;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlNameIdFormats.NAMEID_FORMAT_EMAIL;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlNameIdFormats.NAMEID_FORMAT_PERSISTENT;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlNameIdFormats.NAMEID_FORMAT_TRANSIENT;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlNameIdFormats.NAMEID_FORMAT_UNSPECIFIED;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlNameIdFormats.NAMEID_FORMAT_X509SUBJECT;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_DIGEST_SHA256;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
@ExtendWith(ScreenshotOnFailExtension.class)
public class SamlLoginIT {

    private static final String MARISSA2_USERNAME = "marissa2";
    private static final String MARISSA2_PASSWORD = "saml2";
    private static final String MARISSA3_USERNAME = "marissa3";
    private static final String MARISSA3_PASSWORD = "saml2";
    private static final String MARISSA4_USERNAME = "marissa4";
    private static final String MARISSA4_EMAIL = "marissa4@test.org";
    private static final String MARISSA4_PASSWORD = "saml2";
    private static final String SAML_ORIGIN = "simplesamlphp";
    private static final By byUsername = By.name("username");
    private static final By byPassword = By.name("password");

    @Autowired
    @RegisterExtension
    private IntegrationTestExtension integrationTestExtension;

    @Autowired
    RestOperations restOperations;

    @Autowired
    UaaWebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Autowired
    TestAccounts testAccounts;

    @Autowired
    TestClient testClient;

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

    public static String getValidRandomIDPMetaData() {
        return MockMvcUtils.IDP_META_DATA.formatted(new RandomValueStringGenerator().generate());
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

    @Test
    void samlSPMetadata() {
        RestTemplate request = new RestTemplate();
        ResponseEntity<String> response = request.getForEntity("%s/saml/metadata".formatted(baseUrl), String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        String metadataXml = response.getBody();
        // CR carriage return must not be in output
        assertThat(metadataXml).doesNotContain("&#13;", "\r\n");
        XmlAssert xmlAssert = XmlAssert.assertThat(metadataXml).withNamespaceContext(xmlNamespaces());

        // The SAML SP metadata should match the following UAA configs:
        // login.entityID
        xmlAssert.valueByXPath("//md:EntityDescriptor/@entityID").isEqualTo("cloudfoundry-saml-login");
        // login.saml.signRequest
        xmlAssert.valueByXPath("//md:EntityDescriptor/md:SPSSODescriptor/@AuthnRequestsSigned").isEqualTo(true);
        // login.saml.wantAssertionSigned
        xmlAssert.valueByXPath("//md:EntityDescriptor/md:SPSSODescriptor/@WantAssertionsSigned").isEqualTo(true);
        // the AssertionConsumerService endpoint needs to be: /saml/SSO/alias/[UAA-wide SAML entity ID, aka UAA.yml's login.saml.entityIDAlias or login.entityID]
        xmlAssert.valueByXPath("//md:EntityDescriptor/md:SPSSODescriptor/md:AssertionConsumerService/@Location")
                .contains("localhost", "/saml/SSO/alias/cloudfoundry-saml-login");
        //  login.saml.signatureAlgorithm
        xmlAssert.valueByXPath("/md:EntityDescriptor/ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm").isEqualTo(ALGO_ID_SIGNATURE_RSA_SHA256);
        xmlAssert.valueByXPath("/md:EntityDescriptor/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm").isEqualTo(ALGO_ID_DIGEST_SHA256);
        xmlAssert.nodesByXPath("/md:EntityDescriptor/ds:Signature/ds:SignatureValue").exist();
        // CR carriage return is not visible in XML Assert anymore, but stay we check even here
        xmlAssert.nodesByXPath("/md:EntityDescriptor/ds:Signature/ds:SignatureValue").asString().doesNotContain("&#13;", "\r\n");
        xmlAssert.nodesByXPath("/md:EntityDescriptor/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue").exist();
        // login.saml.nameID
        xmlAssert.nodesByXPath("/md:EntityDescriptor/md:SPSSODescriptor/md:NameIDFormat")
                .extractingText()
                .contains(NAMEID_FORMAT_UNSPECIFIED, NAMEID_FORMAT_EMAIL, NAMEID_FORMAT_X509SUBJECT,
                        NAMEID_FORMAT_PERSISTENT, NAMEID_FORMAT_TRANSIENT);

        assertThat(response.getHeaders().getContentDisposition().getFilename()).isEqualTo("saml-sp.xml");
    }

    @Test
    void samlSPMetadataForZone() {
        String zoneId = "testzone1";
        String zoneUrl = baseUrl.replace("localhost", "%s.localhost".formatted(zoneId));

        //identity client token
        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
        IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );

        //create the zone
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.getCorsPolicy().getDefaultConfiguration().setAllowedMethods(List.of(GET.toString(), POST.toString()));
        config.getSamlConfig().setEntityID("%s-saml-login".formatted(zoneId));
        config.getSamlConfig().setWantAssertionSigned(false);
        config.getSamlConfig().setRequestSigned(false);
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId, config);

        RestTemplate request = new RestTemplate();
        ResponseEntity<String> response = request.getForEntity("%s/saml/metadata".formatted(zoneUrl), String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        String metadataXml = response.getBody();
        // CR carriage return must not be in output
        assertThat(metadataXml).doesNotContain("&#13;", "\r\n");
        XmlAssert xmlAssert = XmlAssert.assertThat(metadataXml).withNamespaceContext(xmlNamespaces());

        // The SAML SP metadata should match the following UAA configs:
        // id zone config's samlConfig.entityID
        xmlAssert.valueByXPath("//md:EntityDescriptor/@entityID").isEqualTo("testzone1-saml-login");
        // determined by zone config field: config.samlConfig.requestSigned
        xmlAssert.valueByXPath("//md:EntityDescriptor/ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm").isEqualTo(ALGO_ID_SIGNATURE_RSA_SHA256);
        xmlAssert.valueByXPath("//md:EntityDescriptor/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm").isEqualTo(ALGO_ID_DIGEST_SHA256);

        // determined by zone config field: config.samlConfig.wantAssertionSigned
        xmlAssert.valueByXPath("//md:EntityDescriptor/md:SPSSODescriptor/@WantAssertionsSigned").isEqualTo(false);
        // the AssertionConsumerService endpoint needs to be: /saml/SSO/alias/[zone-subdomain].[UAA-wide SAML entity ID, aka UAA.yml's login.saml.entityIDAlias, or fall back on login.entityID]
        xmlAssert.valueByXPath("//md:EntityDescriptor/md:SPSSODescriptor/md:AssertionConsumerService/@Location")
                .contains("testzone1.localhost")
                .contains("/saml/SSO/alias/testzone1.cloudfoundry-saml-login");
        xmlAssert.nodesByXPath("//md:EntityDescriptor/ds:Signature/ds:SignatureValue").exist();
        // CR carriage return is not visible in XML Assert anymore, but stay we check even here
        xmlAssert.nodesByXPath("/md:EntityDescriptor/ds:Signature/ds:SignatureValue").asString().doesNotContain("&#13;", "\r\n");
        xmlAssert.nodesByXPath("//md:EntityDescriptor/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue").exist();

        assertThat(response.getHeaders().getContentDisposition().getFilename()).isEqualTo("saml-testzone1-sp.xml");
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
        assertThat(jsonResponseEntity.getHeaders().getFirst("Content-Type")).contains(APPLICATION_JSON_VALUE);

        HttpHeaders htmlHeaders = new HttpHeaders();
        htmlHeaders.add("Accept", "text/html");
        ResponseEntity<Void> htmlResponseEntity = restOperations.exchange(loginUrl,
                HttpMethod.GET,
                new HttpEntity<>(htmlHeaders),
                Void.class);
        assertThat(htmlResponseEntity.getHeaders().getFirst("Content-Type")).contains(TEXT_HTML_VALUE);

        HttpHeaders defaultHeaders = new HttpHeaders();
        defaultHeaders.add("Accept", "*/*");
        ResponseEntity<Void> defaultResponseEntity = restOperations.exchange(loginUrl,
                HttpMethod.GET,
                new HttpEntity<>(defaultHeaders),
                Void.class);
        assertThat(defaultResponseEntity.getHeaders().getFirst("Content-Type")).contains(TEXT_HTML_VALUE);
    }

    @Test
    void simpleSamlPhpPasscodeRedirect() {
        createIdentityProvider(SAML_ORIGIN);

        PasscodePage.assertThatRequestPasscode_goesToLoginPage(webDriver, baseUrl)
                .assertThatSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .assertThatLogin_goesToPasscodePage(testAccounts.getUserName(), testAccounts.getPassword());
    }

    @Test
    void simpleSamlLoginWithAddShadowUserOnLoginFalse() {
        // Deleting marissa@test.org from simplesamlphp because previous SAML authentications automatically
        // create a UAA user with the email address as the username.
        deleteUser(SAML_ORIGIN, testAccounts.getEmail());

        IdentityProvider<SamlIdentityProviderDefinition> provider = IntegrationTestUtils.createIdentityProvider(SAML_ORIGIN, false, baseUrl, serverRunning, samlServerConfig.getSamlServerUrl());
        String clientId = "app-addnew-false" + new RandomValueStringGenerator().generate();
        String redirectUri = "http://nosuchhostname:0/nosuchendpoint";
        createClientAndSpecifyProvider(clientId, provider, redirectUri);

        OauthAuthorizeEndpoint
                .assertThatAuthorize_goesToSamlLoginPage(webDriver, baseUrl, redirectUri, clientId, "code")
                .assertThatLogin_goesToCustomErrorPage(
                        testAccounts.getUserName(),
                        testAccounts.getPassword(),
                        "%s?error=access_denied&error_description=SAML%%20user%%20does%%20not%%20exist.%%20You%%20can%%20correct%%20this%%20by%%20creating%%20a%%20shadow%%20user%%20for%%20the%%20SAML%%20user.".formatted(redirectUri));
    }

    @Test
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
        String groupId = IntegrationTestUtils.findGroupId(adminClient, baseUrl, "zones.%s.admin".formatted(zoneId));
        IntegrationTestUtils.addMemberToGroup(adminClient, baseUrl, user.getId(), groupId);

        //get the zone admin token
        String zoneAdminToken =
                IntegrationTestUtils.getAccessTokenByAuthCode(serverRunning,
                        UaaTestAccounts.standard(serverRunning),
                        "identity",
                        "identitysecret",
                        email,
                        "secr3T");

        SamlIdentityProviderDefinition samlIdentityProviderDefinition = createSimplePHPSamlIDP(SAML_ORIGIN, "testzone3", samlServerConfig.getSamlServerUrl());
        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setIdentityZoneId(zoneId);
        provider.setType(OriginKeys.SAML);
        provider.setActive(true);
        provider.setConfig(samlIdentityProviderDefinition);
        provider.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        provider.setName("simplesamlphp for testzone2");

        IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);

        HomePage.assertThatGoHome_redirectsToLoginPage(webDriver, zoneUrl)
                .assertThatSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .assertThatLogin_goesToSamlErrorPage(testAccounts.getUserName(), testAccounts.getPassword())
                .assertThatPageSource().contains("Invalid destination");
    }

    @Test
    void simpleSamlPhpLogin() {
        createIdentityProvider(SAML_ORIGIN);

        Long beforeTest = System.currentTimeMillis();
        LoginPage.go(webDriver, baseUrl)
                .assertThatSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .assertThatLogin_goesToHomePage(testAccounts.getUserName(), testAccounts.getPassword());
        Long afterTest = System.currentTimeMillis();

        String zoneAdminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "admin", "adminsecret");
        ScimUser user = IntegrationTestUtils.getUser(zoneAdminToken, baseUrl, SAML_ORIGIN, testAccounts.getEmail());
        IntegrationTestUtils.validateUserLastLogon(user, beforeTest, afterTest);
    }

    @Test
    void idpInitiatedLogin() {
        createIdentityProvider(SAML_ORIGIN);
        webDriver.get("%s/saml2/idp/SSOService.php?spentityid=cloudfoundry-saml-login".formatted(samlServerConfig.getSamlServerUrl()));
        new SamlLoginPage(webDriver)
                .assertThatLogin_goesToHomePage(testAccounts.getUserName(), testAccounts.getPassword());
    }

    @Test
    void simpleSamlPhpLoginDisplaysLastLogin() {
        createIdentityProvider(SAML_ORIGIN);

        Long beforeTest = System.currentTimeMillis();
        HomePage homePage = LoginPage.go(webDriver, baseUrl)
                .assertThatSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .assertThatLogin_goesToHomePage(testAccounts.getUserName(), testAccounts.getPassword())
                .assertThatLogout_goesToLoginPage(baseUrl)
                .assertThatSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .assertThatLogin_goesToHomePage(testAccounts.getUserName(), testAccounts.getPassword());
        assertThat(homePage.hasLastLoginTime()).isTrue();

        Long afterTest = System.currentTimeMillis();
        String zoneAdminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "admin", "adminsecret");
        ScimUser user = IntegrationTestUtils.getUser(zoneAdminToken, baseUrl, SAML_ORIGIN, testAccounts.getEmail());
        IntegrationTestUtils.validateUserLastLogon(user, beforeTest, afterTest);
    }

    @Test
    void singleLogout() {
        createIdentityProvider(SAML_ORIGIN);

        LoginPage.go(webDriver, baseUrl)
                .assertThatSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .assertThatLogin_goesToHomePage(testAccounts.getUserName(), testAccounts.getPassword())
                .assertThatLogout_goesToLoginPage(baseUrl)
                .assertThatSamlLink_goesToSamlLoginPage(SAML_ORIGIN);
    }

    @Test
    void idpInitiatedLogout() {
        createIdentityProvider(SAML_ORIGIN);

        LoginPage.go(webDriver, baseUrl)
                .assertThatSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .assertThatLogin_goesToHomePage(testAccounts.getUserName(), testAccounts.getPassword());

        // Logout via IDP
        webDriver.get("%s/saml2/idp/SingleLogoutService.php?ReturnTo=%1$s/%s".formatted(samlServerConfig.getSamlServerUrl(), samlServerConfig.getWelcomePath()));
        // UAA should redirect to the welcome page
        new SamlWelcomePage(webDriver, samlServerConfig);

        // UAA Should no longer be logged in
        HomePage.assertThatGoHome_redirectsToLoginPage(webDriver, baseUrl);
    }

    @Test
    void singleLogoutWithNoLogoutUrlOnIDPWithLogoutRedirect() {
        String zoneId = "testzone2";
        String zoneUrl = baseUrl.replace("localhost", "%s.localhost".formatted(zoneId));

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
        String groupId = IntegrationTestUtils.findGroupId(adminClient, baseUrl, "zones.%s.admin".formatted(zoneId));
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
        loginPage.assertThatTitle().contains("testzone2");
        loginPage.assertThatSamlLink_goesToSamlLoginPage("simplesamlphp")
                .assertThatLogin_goesToHomePage(testAccounts.getUserName(), testAccounts.getPassword());

        String redirectUrl = "%s/login?test=test".formatted(zoneUrl);
        UaaClientDetails clientDetails = new UaaClientDetails("test-logout-redirect", null, null, GRANT_TYPE_AUTHORIZATION_CODE, null);
        clientDetails.setRegisteredRedirectUri(Collections.singleton(redirectUrl));
        clientDetails.setClientSecret("secret");
        IntegrationTestUtils.createOrUpdateClient(zoneAdminToken, baseUrl, zoneId, clientDetails);

        LogoutDoEndpoint.logout_goesToLoginPage(webDriver, zoneUrl, redirectUrl, "test-logout-redirect")
                .assertThatUrl().isEqualTo(redirectUrl);
    }

    @Test
    void singleLogoutWithNoLogoutUrlOnIDP() {
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
                .assertThatSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .assertThatLogin_goesToHomePage(testAccounts.getUserName(), testAccounts.getPassword())
                .assertThatLogout_goesToLoginPage(baseUrl)
                // Local Logout, but not logged out of IDP, login should skip U/P prompt
                .assertThatSamlLink_goesToHomePage(SAML_ORIGIN);
    }

    @Test
    void groupIntegration() {
        createIdentityProvider(SAML_ORIGIN);
        LoginPage.go(webDriver, baseUrl)
                .assertThatSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .assertThatLogin_goesToHomePage(MARISSA4_USERNAME, MARISSA4_PASSWORD);
    }

    @Test
    void faviconShouldNotSave() {
        createIdentityProvider(SAML_ORIGIN);
        FaviconElement.getDefaultIcon(webDriver, baseUrl);
        LoginPage.go(webDriver, baseUrl)
                .assertThatSamlLink_goesToSamlLoginPage(SAML_ORIGIN)
                .assertThatLogin_goesToHomePage(MARISSA4_USERNAME, MARISSA4_PASSWORD);
    }

    protected IdentityProvider<SamlIdentityProviderDefinition> createIdentityProvider(String originKey) {
        return IntegrationTestUtils.createIdentityProvider(originKey, true, baseUrl, serverRunning, samlServerConfig.getSamlServerUrl());
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
        String zoneUrl = baseUrl.replace("localhost", "%s.localhost".formatted(zoneId));

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
        String groupId = IntegrationTestUtils.findGroupId(adminClient, baseUrl, "zones.%s.admin".formatted(zoneId));
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
        webDriver.get("%s/logout.do".formatted(zoneUrl));
        webDriver.get("%s/invitations/accept?code=%s".formatted(zoneUrl, code));

        //redirected to saml login
        webDriver.findElement(By.xpath(samlServerConfig.getLoginPromptXpathExpr()));
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

        webDriver.get("%s/logout.do".formatted(baseUrl));
        webDriver.get("%s/logout.do".formatted(zoneUrl));
        SamlLogoutAuthSourceEndpoint.assertThatLogoutAuthSource_goesToSamlWelcomePage(webDriver, samlServerConfig);
    }

    @Test
    void relayStateRedirectFromIdpInitiatedLogin() {
        createIdentityProvider(SAML_ORIGIN);

        webDriver.get("%s/saml2/idp/SSOService.php?spentityid=cloudfoundry-saml-login&RelayState=https://www.google.com".formatted(samlServerConfig.getSamlServerUrl()));

        // we should now be in the Simple SAML PHP site
        webDriver.findElement(By.xpath(samlServerConfig.getLoginPromptXpathExpr()));
        sendCredentials(testAccounts.getUserName(), testAccounts.getPassword());
        Page.assertThatUrlEventuallySatisfies(webDriver,
                assertUrl -> assertUrl.startsWith("https://www.google.com"));

        webDriver.get("%s/logout.do".formatted(baseUrl));
    }

    @Test
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
        String groupId = IntegrationTestUtils.findGroupId(adminClient, baseUrl, "zones.%s.admin".formatted(zoneId));
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

        webDriver.get("%s/logout.do".formatted(zoneUrl));

        String authUrl = "%s/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&state=8tp0tR".formatted(zoneUrl, clientId, URLEncoder.encode(zoneUrl, StandardCharsets.UTF_8));
        webDriver.get(authUrl);

        //we should now be in the Simple SAML PHP site
        webDriver.findElement(By.xpath(samlServerConfig.getLoginPromptXpathExpr()));
        sendCredentials(testAccounts.getUserName(), "koala");

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Where to?");
        webDriver.get("%s/logout.do".formatted(baseUrl));
        webDriver.get("%s/logout.do".formatted(zoneUrl));
    }

    @Test
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
        String groupId = IntegrationTestUtils.findGroupId(adminClient, baseUrl, "zones.%s.admin".formatted(zoneId));
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

        List<String> idps = List.of(provider.getOriginKey());

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

        webDriver.get("%s/logout.do".formatted(zoneUrl));

        String authUrl = "%s/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&state=8tp0tR"
                .formatted(zoneUrl, clientDetails.getClientId(), URLEncoder.encode(zoneUrl, StandardCharsets.UTF_8));
        webDriver.get(authUrl);

        //we should now be in the Simple SAML PHP site
        webDriver.findElement(By.xpath(samlServerConfig.getLoginPromptXpathExpr()));
        sendCredentials(MARISSA4_USERNAME, MARISSA4_PASSWORD);

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Where to?");
        webDriver.get("%s/logout.do".formatted(baseUrl));
        webDriver.get("%s/logout.do".formatted(zoneUrl));

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
        samlIdentityProviderDefinition1.setLinkText("Dummy SAML provider");
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
        webDriver.get("%s/logout.do".formatted(baseUrl));
        webDriver.get("%s/logout.do".formatted(testZone1Url));
        webDriver.get("%s/login".formatted(testZone1Url));
        assertThat(webDriver.getTitle()).isEqualTo(zone.getName());

        // the first provider is shown
        List<WebElement> elements = webDriver.findElements(By.xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"));
        assertThat(elements).hasSize(1);
        // the dummy provider is shown
        elements = webDriver.findElements(By.xpath("//a[text()='" + samlIdentityProviderDefinition1.getLinkText() + "']"));
        assertThat(elements).hasSize(1);

        // click on the first provider to login
        WebElement element = webDriver.findElement(By.xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"));
        element.click();
        webDriver.findElement(By.xpath(samlServerConfig.getLoginPromptXpathExpr()));
        sendCredentials(testAccounts.getUserName(), testAccounts.getPassword());
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Where to?");

        webDriver.get("%s/logout.do".formatted(baseUrl));
        webDriver.get("%s/logout.do".formatted(testZone1Url));

        //disable the first provider
        SamlLogoutAuthSourceEndpoint.assertThatLogoutAuthSource_goesToSamlWelcomePage(webDriver, samlServerConfig);
        provider.setActive(false);
        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertThat(provider.getId()).isNotNull();
        webDriver.get("%s/logout.do".formatted(testZone1Url));
        assertThat(webDriver.getTitle()).isEqualTo(zone.getName());
        // the first provider is not shown
        elements = webDriver.findElements(By.xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"));
        assertThat(elements).isEmpty();
        // the dummy provider is shown
        elements = webDriver.findElements(By.xpath("//a[text()='" + samlIdentityProviderDefinition1.getLinkText() + "']"));
        assertThat(elements).hasSize(1);

        //enable the first provider
        provider.setActive(true);
        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertThat(provider.getId()).isNotNull();
        webDriver.get("%s/login".formatted(testZone1Url));
        assertThat(webDriver.getTitle()).isEqualTo(zone.getName());
        // the first provider is shown
        elements = webDriver.findElements(By.xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"));
        assertThat(elements).hasSize(1);
        // the dummy provider is shown
        elements = webDriver.findElements(By.xpath("//a[text()='" + samlIdentityProviderDefinition1.getLinkText() + "']"));
        assertThat(elements).hasSize(1);
    }

    @Test
    void loginPageShowsIDPsForAuthCodeClient() {
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

        webDriver.get("%s/oauth/authorize?client_id=%s&redirect_uri=http%%3A%%2F%%2Flocalhost%%3A8888%%2Flogin&response_type=code&state=8tp0tR".formatted(baseUrl, clientId));
        assertThat(webDriver.findElement(By.xpath("//a[text()='" + provider.getConfig().getLinkText() + "']"))).isNotNull();
        assertThat(webDriver.findElement(By.xpath("//a[text()='" + provider2.getConfig().getLinkText() + "']"))).isNotNull();
    }

    @Test
    void loginSamlOnlyProviderNoUsernamePassword() {
        IdentityProvider<SamlIdentityProviderDefinition> provider = createIdentityProvider(SAML_ORIGIN);
        IdentityProvider<SamlIdentityProviderDefinition> provider2 = createIdentityProvider("simplesamlphp2");
        List<String> idps = Arrays.asList(provider.getOriginKey(), provider2.getOriginKey());
        webDriver.get("%s/logout.do".formatted(baseUrl));
        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");

        String clientId = UUID.randomUUID().toString();
        UaaClientDetails clientDetails = new UaaClientDetails(clientId, null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.none", "http://localhost:8080/uaa/login");
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);
        testClient.createClient(adminAccessToken, clientDetails);
        webDriver.get("%s/oauth/authorize?client_id=%s&redirect_uri=http%%3A%%2F%%2Flocalhost%%3A8080%%2Fuaa%%3Alogin&response_type=code&state=8tp0tR".formatted(baseUrl, clientId));

        assertThatThrownBy(() -> webDriver.findElement(byUsername))
                .isInstanceOf(NoSuchElementException.class);
        assertThatThrownBy(() -> webDriver.findElement(byPassword))
                .isInstanceOf(NoSuchElementException.class);

        webDriver.get("%s/logout.do".formatted(baseUrl));
    }

    @Test
    void samlLoginClientIDPAuthorizationAutomaticRedirect() {
        webDriver.get("%s/logout.do".formatted(baseUrl));
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
        webDriver.findElement(By.xpath(samlServerConfig.getLoginPromptXpathExpr()));
        sendCredentials(testAccounts.getUserName(), "koala");

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Where to?");
        webDriver.get("%s/logout.do".formatted(baseUrl));
    }

    @Test
    void loginClientIDPAuthorizationAlreadyLoggedIn() {
        webDriver.get("%s/logout.do".formatted(baseUrl));
        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.read clients.write clients.secret clients.admin");

        String clientId = UUID.randomUUID().toString();
        UaaClientDetails clientDetails = new UaaClientDetails(clientId, null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.none", "http://localhost:8080/login");
        clientDetails.setClientSecret("secret");
        List<String> idps = Collections.singletonList("okta-local"); //not authorized for the current IDP
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);

        testClient.createClient(adminAccessToken, clientDetails);

        sendCredentials(testAccounts.getUserName(), "koala", By.xpath("//input[@value='Sign in']"));

        webDriver.get("%s/oauth/authorize?client_id=%s&redirect_uri=http%%3A%%2F%%2Flocalhost%%3A8888%%2Flogin&response_type=code&state=8tp0tR".formatted(baseUrl, clientId));

        assertThat(webDriver.findElement(By.cssSelector("p")).getText()).contains(clientId + " does not support your identity provider. To log into an identity provider supported by the application");
        webDriver.get("%s/logout.do".formatted(baseUrl));
    }

    @Test
    void springSamlEndpointsWithEmptyContext() throws IOException {
        CallEmptyPageAndCheckHttpStatusCode("/saml/web/metadata/login", 404);
        // These endpoints are now redirect to /login
        CallEmptyPageAndCheckHttpStatusCode("/saml/SingleLogout/alias/foo", 302);
        CallEmptyPageAndCheckHttpStatusCode("/saml/login/alias/foo", 302);
        // and to /saml_error
        CallEmptyPageAndCheckHttpStatusCode("/saml/SSO/alias/foo", 302);
    }

    @Test
    public void backportFrom77RelayTest() {
        final String SIMPLESAMLPHP_UAA_ACCEPTANCE = "http://simplesamlphp.uaa-acceptance.cf-app.com";
        final String SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR =
                "//h1[contains(text(), 'Enter your username and password')]";

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
        assertThat(provider.getOriginKey()).isEqualTo(provider.getConfig().getIdpEntityAlias());

        String zoneUrl = baseUrl.replace("localhost", "testzone1.localhost");

        webDriver.get(zoneUrl + "/logout.do");

        String samlUrl = SIMPLESAMLPHP_UAA_ACCEPTANCE + "/saml2/idp/SSOService.php?"+
                "spentityid=testzone1.cloudfoundry-saml-login&" +
                "RelayState=https://www.google.com";
        webDriver.get(samlUrl);
        //we should now be in the Simple SAML PHP site
        webDriver.findElement(By.xpath(SIMPLESAMLPHP_LOGIN_PROMPT_XPATH_EXPR));
        sendCredentials(testAccounts.getUserName(), "koala");

        Page.assertThatUrlEventuallySatisfies(webDriver,
                assertUrl -> assertUrl.startsWith("https://www.google.com"));
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(zoneUrl + "/logout.do");
    }

    public SamlIdentityProviderDefinition createTestZone2IDP(String alias) {
        return createSimplePHPSamlIDP(alias, "testzone2", samlServerConfig.getSamlServerUrl());
    }

    public SamlIdentityProviderDefinition createTestZone1IDP(String alias) {
        return createSimplePHPSamlIDP(alias, "testzone1", samlServerConfig.getSamlServerUrl());
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
        webDriver.findElement(byUsername).clear();
        webDriver.findElement(byUsername).sendKeys(username);
        webDriver.findElement(byPassword).sendKeys(password);
        webDriver.clickAndWait(loginButtonSelector);
    }

    private void sendCredentials(String username, String password) {
        sendCredentials(username, password, By.id("submit_button"));
    }

    private void CallEmptyPageAndCheckHttpStatusCode(String errorPath, int codeExpected) throws IOException {
        HttpURLConnection cn = (HttpURLConnection) new URL(baseUrl + errorPath).openConnection();
        cn.setInstanceFollowRedirects(false);
        assertThat(cn.getResponseCode())
                .as("Check status code from %s", errorPath)
                .isEqualTo(codeExpected);
    }
}
