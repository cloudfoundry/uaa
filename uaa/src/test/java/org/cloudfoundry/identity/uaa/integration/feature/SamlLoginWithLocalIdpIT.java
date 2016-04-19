/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import org.apache.commons.lang.StringUtils;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.login.test.LoginServerClassRunner;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProvider;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assume.assumeTrue;

@RunWith(LoginServerClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class SamlLoginWithLocalIdpIT {

    public static final String IDP_ENTITY_ID = "cloudfoundry-saml-login";

    @Autowired
    @Rule
    public IntegrationTestRule integrationTestRule;

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

    @Before
    public void clearWebDriverOfCookies() throws Exception {
        webDriver.get(baseUrl + "/logout.do");
        webDriver.manage().deleteAllCookies();
        webDriver.get(baseUrl.replace("localhost", "testzone1.localhost") + "/logout.do");
        webDriver.manage().deleteAllCookies();
        webDriver.get(baseUrl.replace("localhost", "testzone2.localhost") + "/logout.do");
        webDriver.manage().deleteAllCookies();
        webDriver.get("http://simplesamlphp.cfapps.io/module.php/core/authenticate.php?as=example-userpass&logout");
        webDriver.get("http://simplesamlphp2.cfapps.io/module.php/core/authenticate.php?as=example-userpass&logout");
    }

    /**
     * Test that can UAA generate it's own SAML identity provider metadata.
     */
    @Test
    public void testDownloadSamlIdpMetadata() {
        String entityId = IDP_ENTITY_ID;
        SamlIdentityProviderDefinition idpDefinition = createLocalSamlIdpDefinition(entityId, "uaa");
        Assert.assertTrue(idpDefinition.getMetaDataLocation().contains(IDPSSODescriptor.DEFAULT_ELEMENT_LOCAL_NAME));
        Assert.assertTrue(idpDefinition.getMetaDataLocation().contains("entityID=\"" + entityId + "\""));
    }

    /**
     * Test that we can create an identity provider in UAA using UAA's own SAML identity provider metadata.
     */
    @Test
    public void testCreateSamlIdp() throws Exception {
        SamlIdentityProviderDefinition idpDef = createLocalSamlIdpDefinition(IDP_ENTITY_ID, OriginKeys.UAA);
        IntegrationTestUtils.createIdentityProvider("Local SAML IdP", IDP_ENTITY_ID, true, this.baseUrl,
                this.serverRunning, idpDef);
    }

    public static SamlIdentityProviderDefinition createLocalSamlIdpDefinition(String alias, String zoneId) {

        String url;
        if (StringUtils.isNotEmpty(zoneId) && !zoneId.equals("uaa")) {
            url = "http://" + zoneId + ".localhost:8080/uaa/saml/idp/metadata";
        } else {
            url = "http://localhost:8080/uaa/saml/idp/metadata";
        }

        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", "application/samlmetadata+xml");
        headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        HttpEntity<String> getHeaders = new HttpEntity<String>(headers);
        ResponseEntity<String> metadataResponse = client.exchange(url, HttpMethod.GET, getHeaders, String.class);

        String idpMetaData = metadataResponse.getBody();
        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
        def.setZoneId(zoneId);
        def.setMetaDataLocation(idpMetaData);
        def.setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        def.setAssertionConsumerIndex(0);
        def.setMetadataTrustCheck(false);
        def.setShowSamlLink(true);
        if (StringUtils.isNotEmpty(zoneId) && !zoneId.equals(OriginKeys.UAA)) {
            def.setIdpEntityAlias(zoneId + "." + alias);
            def.setLinkText("Login with Local SAML IdP(" + zoneId + "." + alias + ")");
        } else {
            def.setIdpEntityAlias(alias);
            def.setLinkText("Login with Local SAML IdP(" + alias + ")");
        }
        return def;
    }

    @Test
    public void testCreateSamlSp() throws Exception {
        SamlServiceProviderDefinition spDef = createLocalSamlSpDefinition("cloudfoundry-saml-login", "uaa");
        createSamlServiceProvider("Local SAML SP", "cloudfoundry-saml-login", baseUrl, serverRunning, spDef);
    }

    public static SamlServiceProviderDefinition createLocalSamlSpDefinition(String alias, String zoneId) {

        String url;
        if (StringUtils.isNotEmpty(zoneId) && !zoneId.equals("uaa")) {
            url = "http://" + zoneId + ".localhost:8080/uaa/saml/metadata/alias/" + zoneId + "." + alias;
        } else {
            url = "http://localhost:8080/uaa/saml/metadata/alias/" + alias;
        }

        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", "application/samlmetadata+xml");
        headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        HttpEntity<String> getHeaders = new HttpEntity<String>(headers);
        ResponseEntity<String> metadataResponse = client.exchange(url, HttpMethod.GET, getHeaders, String.class);

        String spMetaData = metadataResponse.getBody();
        SamlServiceProviderDefinition def = new SamlServiceProviderDefinition();
        def.setMetaDataLocation(spMetaData);
        def.setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        def.setSingleSignOnServiceIndex(0);
        def.setMetadataTrustCheck(false);
        return def;
    }

    public static SamlServiceProviderDefinition createZone1SamlSpDefinition(String alias) {
        return createLocalSamlSpDefinition(alias, "testzone1");
    }

    public static SamlServiceProviderDefinition createZone2SamlSpDefinition(String alias) {
        return createLocalSamlSpDefinition(alias, "testzone2");
    }

    public static SamlServiceProvider createSamlServiceProvider(String name, String entityId, String baseUrl,
            ServerRunning serverRunning, SamlServiceProviderDefinition samlServiceProviderDefinition) throws Exception {
        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(IntegrationTestUtils
                .getClientCredentialsResource(baseUrl, new String[0], "identity", "identitysecret"));
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret"));
        String email = new RandomValueStringGenerator().generate() + "@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl, email, "firstname", "lastname", email,
                true);
        IntegrationTestUtils.makeZoneAdmin(identityClient, baseUrl, user.getId(), OriginKeys.UAA);

        String zoneAdminToken = IntegrationTestUtils.getAuthorizationCodeToken(serverRunning,
                UaaTestAccounts.standard(serverRunning), "identity", "identitysecret", email, "secr3T");

        SamlServiceProvider provider = new SamlServiceProvider();
        provider.setConfig(samlServiceProviderDefinition);
        provider.setIdentityZoneId(OriginKeys.UAA);
        provider.setActive(true);
        provider.setEntityId(entityId);
        provider.setName(name);
        provider = createOrUpdateSamlServiceProvider(zoneAdminToken, baseUrl, provider);
        assertNotNull(provider.getId());
        return provider;
    }

    public static SamlServiceProvider createOrUpdateSamlServiceProvider(String accessToken, String url,
            SamlServiceProvider provider) {
        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + accessToken);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.add(IdentityZoneSwitchingFilter.HEADER, provider.getIdentityZoneId());
        List<SamlServiceProvider> existing = getSamlServiceProviders(accessToken, url, provider.getIdentityZoneId());
        if (existing != null) {
            for (SamlServiceProvider p : existing) {
                if (p.getEntityId().equals(provider.getEntityId())
                        && p.getIdentityZoneId().equals(provider.getIdentityZoneId())) {
                    provider.setId(p.getId());
                    HttpEntity<SamlServiceProvider> putHeaders = new HttpEntity<SamlServiceProvider>(provider, headers);
                    ResponseEntity<String> providerPut = client.exchange(url + "/saml/service-providers/{id}",
                            HttpMethod.PUT, putHeaders, String.class, provider.getId());
                    if (providerPut.getStatusCode() == HttpStatus.OK) {
                        return JsonUtils.readValue(providerPut.getBody(), SamlServiceProvider.class);
                    }
                }
            }
        }

        HttpEntity<SamlServiceProvider> postHeaders = new HttpEntity<SamlServiceProvider>(provider, headers);
        ResponseEntity<String> providerPost = client.exchange(url + "/saml/service-providers/{id}", HttpMethod.POST,
                postHeaders, String.class, provider.getId());
        if (providerPost.getStatusCode() == HttpStatus.CREATED) {
            return JsonUtils.readValue(providerPost.getBody(), SamlServiceProvider.class);
        }
        throw new IllegalStateException(
                "Invalid result code returned, unable to create identity provider:" + providerPost.getStatusCode());
    }

    public static List<SamlServiceProvider> getSamlServiceProviders(String zoneAdminToken, String url, String zoneId) {
        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + zoneAdminToken);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        HttpEntity<String> getHeaders = new HttpEntity<String>(headers);
        ResponseEntity<String> providerGet = client.exchange(url + "/saml/service-providers", HttpMethod.GET, getHeaders,
                String.class);
        if (providerGet != null && providerGet.getStatusCode() == HttpStatus.OK) {
            return JsonUtils.readValue(providerGet.getBody(), new TypeReference<List<SamlServiceProvider>>() {
                // Do nothing.
            });
        }
        return null;
    }

    @Test
    public void testLocalSamlIdpLogin() throws Exception {
        ScimUser user = IntegrationTestUtils.createRandomUser(this.baseUrl);
        testLocalSamlIdpLogin("/login", "Where to?", user.getPrimaryEmail(), "secr3T");
    }

    private void testLocalSamlIdpLogin(String firstUrl, String lookfor, String username, String password)
            throws Exception {
        SamlIdentityProviderDefinition idpDef = createLocalSamlIdpDefinition(IDP_ENTITY_ID, "uaa");
        @SuppressWarnings("unchecked")
        IdentityProvider<SamlIdentityProviderDefinition> provider = IntegrationTestUtils.createIdentityProvider(
                "Local SAML IdP", IDP_ENTITY_ID, true, this.baseUrl, this.serverRunning, idpDef);

        SamlServiceProviderDefinition spDef = createLocalSamlSpDefinition("cloudfoundry-saml-login", "uaa");
        createSamlServiceProvider("Local SAML SP", "cloudfoundry-saml-login", baseUrl, serverRunning, spDef);

        // tells us that we are on travis
        assumeTrue("Expected testzone1/2.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());

        webDriver.get(baseUrl + firstUrl);
        Assert.assertEquals("Cloud Foundry", webDriver.getTitle());
        webDriver.findElement(By.xpath("//a[text()='" + provider.getConfig().getLinkText() + "']")).click();
        webDriver.findElement(By.xpath("//h1[contains(text(), 'Welcome!')]"));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(username);
        webDriver.findElement(By.name("password")).sendKeys(password);
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString(lookfor));

        provider.setActive(false);
        IntegrationTestUtils.updateIdentityProvider(this.baseUrl, this.serverRunning, provider);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testLocalSamlIdpLoginInTestZone1Works() throws Exception {
        assumeTrue("Expected testzone1/2.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());
        String zoneId = "testzone1";

        RestTemplate identityClient = IntegrationTestUtils
                .getClientCredentialsTemplate(IntegrationTestUtils.getClientCredentialsResource(baseUrl,
                        new String[] { "zones.write", "zones.read", "scim.zones" }, "identity", "identitysecret"));
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret"));
        IdentityZone zone = IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId);
        String email = new RandomValueStringGenerator().generate() + "@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl, email, "firstname", "lastname", email,
                true);
        IntegrationTestUtils.makeZoneAdmin(identityClient, baseUrl, user.getId(), zoneId);

        String zoneAdminToken = IntegrationTestUtils.getAuthorizationCodeToken(serverRunning,
                UaaTestAccounts.standard(serverRunning), "identity", "identitysecret", email, "secr3T");

        String testZone1Url = baseUrl.replace("localhost", zoneId + ".localhost");
        String zoneAdminClientId = new RandomValueStringGenerator().generate() + "-" + zoneId + "-admin";
        BaseClientDetails clientDetails = new BaseClientDetails(zoneAdminClientId, null, "uaa.none",
                "client_credentials", "uaa.admin,scim.read,scim.write,uaa.resource", testZone1Url);
        clientDetails.setClientSecret("secret");
        IntegrationTestUtils.createClientAsZoneAdmin(zoneAdminToken, baseUrl, zoneId, clientDetails);

        RestTemplate zoneAdminClient = IntegrationTestUtils.getClientCredentialsTemplate(IntegrationTestUtils
                .getClientCredentialsResource(testZone1Url, new String[0], zoneAdminClientId, "secret"));
        String zoneUserEmail = new RandomValueStringGenerator().generate() + "@samltesting.org";
        IntegrationTestUtils.createUser(zoneAdminClient, testZone1Url, zoneUserEmail, "Dana", "Scully", zoneUserEmail,
                true);

        SamlIdentityProviderDefinition samlIdentityProviderDefinition = createZone1IdpDefinition(IDP_ENTITY_ID);
        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setIdentityZoneId(zoneId);
        provider.setType(OriginKeys.SAML);
        provider.setActive(true);
        provider.setConfig(samlIdentityProviderDefinition);
        provider.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        provider.setName("Local SAML IdP for testzone1");
        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertNotNull(provider.getId());


        SamlServiceProviderDefinition samlServiceProviderDefinition = createZone1SamlSpDefinition("cloudfoundry-saml-login");
        SamlServiceProvider sp = new SamlServiceProvider();
        sp.setIdentityZoneId(zoneId);
        sp.setActive(true);
        sp.setConfig(samlServiceProviderDefinition);
        sp.setEntityId("testzone1.cloudfoundry-saml-login");
        sp.setName("Local SAML SP for testzone1");
        sp = createOrUpdateSamlServiceProvider(zoneAdminToken, baseUrl, sp);

        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(testZone1Url + "/logout.do");
        webDriver.get(testZone1Url + "/login");
        Assert.assertEquals(zone.getName(), webDriver.getTitle());

        List<WebElement> elements = webDriver
                .findElements(By.xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"));
        assertNotNull(elements);
        assertEquals(1, elements.size());

        WebElement element = elements.get(0);
        assertNotNull(element);
        element.click();
        webDriver.findElement(By.xpath("//h1[contains(text(), 'Welcome to The Twiglet Zone[" + zoneId + "]!')]"));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(zoneUserEmail);
        webDriver.findElement(By.name("password")).sendKeys("secr3T");
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Where to?"));

        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(testZone1Url + "/logout.do");

        // disable the provider
        provider.setActive(false);
        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertNotNull(provider.getId());
        webDriver.get(testZone1Url + "/login");
        Assert.assertEquals(zone.getName(), webDriver.getTitle());
        elements = webDriver
                .findElements(By.xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"));
        assertNotNull(elements);
        assertEquals(0, elements.size());

        // enable the provider
        provider.setActive(true);
        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertNotNull(provider.getId());
        webDriver.get(testZone1Url + "/login");
        Assert.assertEquals(zone.getName(), webDriver.getTitle());
        elements = webDriver
                .findElements(By.xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"));
        assertNotNull(elements);
        assertEquals(1, elements.size());
    }

    /**
     * In this test testzone1 acts as the SAML IdP and testzone2 acts as the SAML SP.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testCrossZoneSamlIntegration() throws Exception {
        assumeTrue("Expected testzone1/2.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());
        String idpZoneId = "testzone1";
        String spZoneId = "testzone2";

        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret"));
        RestTemplate identityClient = IntegrationTestUtils
                .getClientCredentialsTemplate(IntegrationTestUtils.getClientCredentialsResource(baseUrl,
                        new String[] { "zones.write", "zones.read", "scim.zones" }, "identity", "identitysecret"));

        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, idpZoneId, idpZoneId);
        String idpZoneAdminEmail = new RandomValueStringGenerator().generate() + "@samltesting.org";
        ScimUser idpZoneAdminUser = IntegrationTestUtils.createUser(adminClient, baseUrl, idpZoneAdminEmail, "firstname", "lastname", idpZoneAdminEmail,
                true);
        IntegrationTestUtils.makeZoneAdmin(identityClient, baseUrl, idpZoneAdminUser.getId(), idpZoneId);
        String idpZoneAdminToken = IntegrationTestUtils.getAuthorizationCodeToken(serverRunning,
                UaaTestAccounts.standard(serverRunning), "identity", "identitysecret", idpZoneAdminEmail, "secr3T");

        String idpZoneUserEmail = new RandomValueStringGenerator().generate() + "@samltesting.org";
        String idpZoneUrl = baseUrl.replace("localhost", idpZoneId + ".localhost");
        createZoneUser(idpZoneId, idpZoneAdminToken, idpZoneUserEmail, idpZoneUrl);

        SamlConfig samlConfig = new SamlConfig();
        samlConfig.setWantAssertionSigned(true);
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setSamlConfig(samlConfig);
        IdentityZone spZone = IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, spZoneId, spZoneId, config );
        String spZoneAdminEmail = new RandomValueStringGenerator().generate() + "@samltesting.org";
        ScimUser spZoneAdminUser = IntegrationTestUtils.createUser(adminClient, baseUrl, spZoneAdminEmail, "firstname", "lastname", spZoneAdminEmail,
                true);
        IntegrationTestUtils.makeZoneAdmin(identityClient, baseUrl, spZoneAdminUser.getId(), spZoneId);
        String spZoneAdminToken = IntegrationTestUtils.getAuthorizationCodeToken(serverRunning,
                UaaTestAccounts.standard(serverRunning), "identity", "identitysecret", spZoneAdminEmail, "secr3T");
        String spZoneUrl = baseUrl.replace("localhost", spZoneId + ".localhost");

        SamlIdentityProviderDefinition samlIdentityProviderDefinition = createZone1IdpDefinition(IDP_ENTITY_ID);
        IdentityProvider<SamlIdentityProviderDefinition> idp = new IdentityProvider<>();
        idp.setIdentityZoneId(spZoneId);
        idp.setType(OriginKeys.SAML);
        idp.setActive(true);
        idp.setConfig(samlIdentityProviderDefinition);
        idp.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        idp.setName("Local SAML IdP for testzone1");
        idp = IntegrationTestUtils.createOrUpdateProvider(spZoneAdminToken, baseUrl, idp);
        assertNotNull(idp.getId());

        SamlServiceProviderDefinition samlServiceProviderDefinition = createZone2SamlSpDefinition("cloudfoundry-saml-login");
        SamlServiceProvider sp = new SamlServiceProvider();
        sp.setIdentityZoneId(idpZoneId);
        sp.setActive(true);
        sp.setConfig(samlServiceProviderDefinition);
        sp.setEntityId("testzone2.cloudfoundry-saml-login");
        sp.setName("Local SAML SP for testzone2");
        sp = createOrUpdateSamlServiceProvider(idpZoneAdminToken, baseUrl, sp);

        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(spZoneUrl + "/logout.do");
        webDriver.get(spZoneUrl + "/login");
        Assert.assertEquals(spZone.getName(), webDriver.getTitle());

        List<WebElement> elements = webDriver
                .findElements(By.xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"));
        assertNotNull(elements);
        assertEquals(1, elements.size());

        WebElement element = elements.get(0);
        assertNotNull(element);
        element.click();
        webDriver.findElement(By.xpath("//h1[contains(text(), 'Welcome to The Twiglet Zone[" + idpZoneId + "]!')]"));
        webDriver.findElement(By.name("username")).clear();
        webDriver.findElement(By.name("username")).sendKeys(idpZoneUserEmail);
        webDriver.findElement(By.name("password")).sendKeys("secr3T");
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Where to?"));

        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(spZoneUrl + "/logout.do");

        // disable the provider
        idp.setActive(false);
        idp = IntegrationTestUtils.createOrUpdateProvider(spZoneAdminToken, baseUrl, idp);
        assertNotNull(idp.getId());
        webDriver.get(spZoneUrl + "/login");
        Assert.assertEquals(spZone.getName(), webDriver.getTitle());
        elements = webDriver
                .findElements(By.xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"));
        assertNotNull(elements);
        assertEquals(0, elements.size());

        // enable the provider
        idp.setActive(true);
        idp = IntegrationTestUtils.createOrUpdateProvider(spZoneAdminToken, baseUrl, idp);
        assertNotNull(idp.getId());
        webDriver.get(spZoneUrl + "/login");
        Assert.assertEquals(spZone.getName(), webDriver.getTitle());
        elements = webDriver
                .findElements(By.xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"));
        assertNotNull(elements);
        assertEquals(1, elements.size());
    }

    private void createZoneUser(String idpZoneId, String zoneAdminToken, String zoneUserEmail, String zoneUrl) throws Exception {
        String zoneAdminClientId = new RandomValueStringGenerator().generate() + "-" + idpZoneId + "-admin";
        BaseClientDetails clientDetails = new BaseClientDetails(zoneAdminClientId, null, "uaa.none",
                "client_credentials", "uaa.admin,scim.read,scim.write,uaa.resource", zoneUrl);
        clientDetails.setClientSecret("secret");
        IntegrationTestUtils.createClientAsZoneAdmin(zoneAdminToken, baseUrl, idpZoneId, clientDetails);

        RestTemplate zoneAdminClient = IntegrationTestUtils.getClientCredentialsTemplate(IntegrationTestUtils
                .getClientCredentialsResource(zoneUrl, new String[0], zoneAdminClientId, "secret"));
        IntegrationTestUtils.createUser(zoneAdminClient, zoneUrl, zoneUserEmail, "Dana", "Scully", zoneUserEmail,
                true);
    }

    protected boolean doesSupportZoneDNS() {
        try {
            return Arrays.equals(Inet4Address.getByName("testzone1.localhost").getAddress(),
                    new byte[] { 127, 0, 0, 1 })
                    && Arrays.equals(Inet4Address.getByName("testzone2.localhost").getAddress(),
                            new byte[] { 127, 0, 0, 1 })
                    && Arrays.equals(Inet4Address.getByName("testzone3.localhost").getAddress(),
                            new byte[] { 127, 0, 0, 1 });
        } catch (UnknownHostException e) {
            return false;
        }
    }

    public SamlIdentityProviderDefinition createZone1IdpDefinition(String alias) {
        return createLocalSamlIdpDefinition(alias, "testzone1");
    }

    public SamlIdentityProviderDefinition createZone2IdpDefinition(String alias) {
        return createLocalSamlIdpDefinition(alias, "testzone2");
    }

    public SamlIdentityProviderDefinition createZone3IdpDefinition(String alias) {
        return createLocalSamlIdpDefinition(alias, "testzone3");
    }

}
