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
import org.cloudfoundry.identity.uaa.oauth.token.CompositeAccessToken;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProvider;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
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
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.By;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
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
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.certificate1;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.certificate2;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.key1;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.key2;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.passphrase1;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.passphrase2;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assume.assumeTrue;


@RunWith(LoginServerClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class SamlLoginWithLocalIdpIT {

    public static final String IDP_ENTITY_ID = "cloudfoundry-saml-login";

    private final SamlTestUtils samlTestUtils = new SamlTestUtils();
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
        samlTestUtils.initialize();
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
        return SamlTestUtils.createLocalSamlIdpDefinition(alias, zoneId, idpMetaData);
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
    public void testInvalidSaml2Bearer() throws Exception {
        SamlIdentityProviderDefinition idpDef = createLocalSamlIdpDefinition(IDP_ENTITY_ID, "uaa");
        @SuppressWarnings("unchecked")
        IdentityProvider<SamlIdentityProviderDefinition> provider = IntegrationTestUtils.createIdentityProvider(
                "Local SAML IdP", IDP_ENTITY_ID, true, this.baseUrl, this.serverRunning, idpDef);
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add("grant_type", "urn:ietf:params:oauth:grant-type:saml2-bearer");
        postBody.add("client_id", "oauth_showcase_saml2_bearer");
        postBody.add("client_secret", "secret");
        postBody.add("assertion",
             "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDI6QXNzZXJ0aW9uIHhtbG5zOnNhbWwyPS" +
             "J1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iXzBkNzhhYTdhLTY4MzctNDUyNi1iNTk4" +
             "LTliZGE0MTI5NTE0YiIgSXNzdWVJbnN0YW50PSIyMDE2LTExLTIyVDIxOjU3OjMwLjI2NVoiIFZlcnNpb249IjIuMC" +
             "IgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIj48c2FtbDI6SXNzdWVyPmNsb3VkZm91" +
             "bmRyeS1zYW1sLWxvZ2luPC9zYW1sMjpJc3N1ZXI-PHNhbWwyOlN1YmplY3Q-PHNhbWwyOk5hbWVJRCBGb3JtYXQ9In" +
             "VybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OnVuc3BlY2lmaWVkIj5Vbml0VGVzdFRlc3RV" +
             "c2VyPC9zYW1sMjpOYW1lSUQ-PHNhbWwyOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZX" +
             "M6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48c2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbkRhdGEgTm90T25PckFmdGVy" +
             "PSIyMDE3LTExLTIyVDIyOjAyOjMwLjI5NloiIFJlY2lwaWVudD0iaHR0cDovL2xvY2FsaG9zdDo4MDgwL3VhYS9vYX" +
             "V0aC90b2tlbiIvPjwvc2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbj48L3NhbWwyOlN1YmplY3Q-PHNhbWwyOkNvbmRp" +
             "dGlvbnMgTm90QmVmb3JlPSIyMDE2LTExLTIyVDIxOjU3OjMwLjI2NVoiIE5vdE9uT3JBZnRlcj0iMjAxNy0xMS0yMl" +
             "QyMjowMjozMC4yOTZaIj48c2FtbDI6QXVkaWVuY2VSZXN0cmljdGlvbj48c2FtbDI6QXVkaWVuY2U-aHR0cDovL2xv" +
             "Y2FsaG9zdDo4MDgwL3VhYS9vYXV0aC90b2tlbjwvc2FtbDI6QXVkaWVuY2U-PC9zYW1sMjpBdWRpZW5jZVJlc3RyaW" +
             "N0aW9uPjwvc2FtbDI6Q29uZGl0aW9ucz48c2FtbDI6QXR0cmlidXRlU3RhdGVtZW50PjxzYW1sMjpBdHRyaWJ1dGUg" +
             "TmFtZT0iR3JvdXBzIj48c2FtbDI6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMD" +
             "AxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI-Y2xpZW50LndyaXRlPC9zYW1sMjpBdHRy" +
             "aWJ1dGVWYWx1ZT48c2FtbDI6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1" +
             "hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI-Y2xpZW50LnJlYWQ8L3NhbWwyOkF0dHJpYnV0" +
             "ZVZhbHVlPjwvc2FtbDI6QXR0cmlidXRlPjwvc2FtbDI6QXR0cmlidXRlU3RhdGVtZW50PjxzYW1sMjpBdXRoblN0YX" +
             "RlbWVudCBBdXRobkluc3RhbnQ9IjIwMTYtMTEtMjJUMjI6MDI6MzAuMjk5WiIgU2Vzc2lvbk5vdE9uT3JBZnRlcj0i" +
             "MjAxNi0xMi0yMlQyMjowMjozMC4yOTlaIj48c2FtbDI6QXV0aG5Db250ZXh0PjxzYW1sMjpBdXRobkNvbnRleHRDbG" +
             "Fzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpQYXNzd29yZDwvc2FtbDI6QXV0aG5D" +
             "b250ZXh0Q2xhc3NSZWY-PC9zYW1sMjpBdXRobkNvbnRleHQ-PC9zYW1sMjpBdXRoblN0YXRlbWVudD48L3NhbWwyOk" +
             "Fzc2VydGlvbj4"
        );

        try {
           restOperations.exchange(baseUrl + "/oauth/token",
               HttpMethod.POST,
               new HttpEntity<>(postBody, headers),
               Void.class);
        } catch ( HttpClientErrorException he ) {
           assertEquals(HttpStatus.UNAUTHORIZED, he.getStatusCode());
        }

        provider.setActive(false);
        IntegrationTestUtils.updateIdentityProvider(this.baseUrl, this.serverRunning, provider);
    }

    @Test
    public void testValidSaml2Bearer() throws Exception {
        SamlIdentityProviderDefinition idpDef = createLocalSamlIdpDefinition(IDP_ENTITY_ID, "uaa");
        @SuppressWarnings("unchecked")
        IdentityProvider<SamlIdentityProviderDefinition> provider = IntegrationTestUtils.createIdentityProvider(
                "Local SAML IdP", IDP_ENTITY_ID, true, this.baseUrl, this.serverRunning, idpDef);
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add("grant_type", "urn:ietf:params:oauth:grant-type:saml2-bearer");
        postBody.add("client_id", "oauth_showcase_saml2_bearer");
        postBody.add("client_secret", "secret");
        postBody.add("assertion", samlTestUtils.mockAssertionEncoded(IDP_ENTITY_ID,
                                                                     "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                                                                     "Saml2BearerIntegrationUser", "http://localhost:8080/uaa/oauth/token/alias/cloudfoundry-saml-login", "cloudfoundry-saml-login"));

        ResponseEntity<CompositeAccessToken> token = restOperations.exchange(baseUrl + "/oauth/token/alias/cloudfoundry-saml-login",
                                                                             HttpMethod.POST, new HttpEntity<>(postBody, headers),
                                                                             CompositeAccessToken.class);

        assertEquals(HttpStatus.OK, token.getStatusCode());
        Assert.assertTrue(token.hasBody());
        provider.setActive(false);
        IntegrationTestUtils.updateIdentityProvider(this.baseUrl, this.serverRunning, provider);
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
        assertEquals("Cloud Foundry", webDriver.getTitle());
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
        assertEquals(zone.getName(), webDriver.getTitle());

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
        assertEquals(zone.getName(), webDriver.getTitle());
        elements = webDriver
                .findElements(By.xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"));
        assertNotNull(elements);
        assertEquals(0, elements.size());

        // enable the provider
        provider.setActive(true);
        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertNotNull(provider.getId());
        webDriver.get(testZone1Url + "/login");
        assertEquals(zone.getName(), webDriver.getTitle());
        elements = webDriver
                .findElements(By.xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"));
        assertNotNull(elements);
        assertEquals(1, elements.size());
    }

    /**
     *
     * In this test testzone1 acts as the SAML IdP and testzone2 acts as the SAML SP.
     * SP is first configured with IDP Metadata that has three SSO Bindings, with Http-Artifact as the first one
     * and SamlAuthnRequest must succeed using the Second configured SSO binding.
     * SP's IDP is updated with Http-Artifact as the only binding configured. The SamlAuthnRequest must fail.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testWebSSOProfileWithArtifactInMetadataSamlIntegration() throws Exception {
        assumeTrue("Expected testzone1/2.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());
        String idpZoneId = "testzone1";
        String spZoneId = "testzone2";

        RestTemplate adminClient =
                IntegrationTestUtils.getClientCredentialsTemplate(
                        IntegrationTestUtils.getClientCredentialsResource(
                                baseUrl, new String[0], "admin", "adminsecret")
                );

        RestTemplate identityClient =
                IntegrationTestUtils.getClientCredentialsTemplate(
                        IntegrationTestUtils.getClientCredentialsResource(
                                baseUrl,new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
                );

        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, idpZoneId, idpZoneId);
        String idpZoneAdminEmail = new RandomValueStringGenerator().generate() + "@samltesting.org";
        ScimUser idpZoneAdminUser = IntegrationTestUtils.createUser(adminClient, baseUrl, idpZoneAdminEmail, "firstname", "lastname", idpZoneAdminEmail, true);
        IntegrationTestUtils.makeZoneAdmin(identityClient, baseUrl, idpZoneAdminUser.getId(), idpZoneId);
        String idpZoneAdminToken =
                IntegrationTestUtils.getAuthorizationCodeToken(
                        serverRunning,
                        UaaTestAccounts.standard(serverRunning),
                        "identity",
                        "identitysecret",
                        idpZoneAdminEmail,
                        "secr3T"
                );

        String idpZoneUserEmail = new RandomValueStringGenerator().generate() + "@samltesting.org";
        String idpZoneUrl = baseUrl.replace("localhost", idpZoneId + ".localhost");
        createZoneUser(idpZoneId, idpZoneAdminToken, idpZoneUserEmail, idpZoneUrl);

        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        IdentityZone spZone = IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, spZoneId, spZoneId, config);

        String spZoneAdminEmail = new RandomValueStringGenerator().generate() + "@samltesting.org";
        ScimUser spZoneAdminUser = IntegrationTestUtils.createUser(
                adminClient,
                baseUrl,
                spZoneAdminEmail,
                "firstname",
                "lastname",
                spZoneAdminEmail,
                true
        );
        IntegrationTestUtils.makeZoneAdmin(identityClient, baseUrl, spZoneAdminUser.getId(), spZoneId);
        String spZoneAdminToken =
                IntegrationTestUtils.getAuthorizationCodeToken(
                        serverRunning,
                        UaaTestAccounts.standard(serverRunning),
                        "identity",
                        "identitysecret",
                        spZoneAdminEmail,
                        "secr3T"
                );
        String spZoneUrl = baseUrl.replace("localhost", spZoneId + ".localhost");

        SamlIdentityProviderDefinition samlIdentityProviderDefinition = createZone1IdpDefinition(IDP_ENTITY_ID);
        samlIdentityProviderDefinition.setMetaDataLocation(SamlTestUtils.SAML_IDP_METADATA_ARTIFACT_FIRST);
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
        samlServiceProviderDefinition.setMetaDataLocation(SamlTestUtils.SAML_SP_METADATA_TESTZONE2);

        sp.setIdentityZoneId(idpZoneId);
        sp.setActive(true);
        sp.setConfig(samlServiceProviderDefinition);
        sp.setEntityId("testzone2.cloudfoundry-saml-login");
        sp.setName("Local SAML SP for testzone2");
        sp = createOrUpdateSamlServiceProvider(idpZoneAdminToken, baseUrl, sp);

        performLogin(idpZoneId, idpZoneUserEmail, idpZoneUrl, spZone, spZoneUrl, samlIdentityProviderDefinition);

        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(spZoneUrl + "/logout.do");

        // Switch up the Identity Provider SSO binding list to Only have the Http-Artifact binding
        samlIdentityProviderDefinition.setMetaDataLocation(SamlTestUtils.SAML_IDP_METADATA_ARTIFACT_ONLY);
        idp.setConfig(samlIdentityProviderDefinition);
        idp.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        idp.setName("Local SAML IdP for testzone1");
        idp = IntegrationTestUtils.createOrUpdateProvider(spZoneAdminToken, baseUrl, idp);
        assertNotNull(idp.getId());
        performLogin(idpZoneId, idpZoneUserEmail, idpZoneUrl, spZone, spZoneUrl, samlIdentityProviderDefinition);
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

        RestTemplate adminClient =
            IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(
                    baseUrl, new String[0], "admin", "adminsecret")
            );

        RestTemplate identityClient =
            IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(
                    baseUrl,new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
            );

        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, idpZoneId, idpZoneId);
        String idpZoneAdminEmail = new RandomValueStringGenerator().generate() + "@samltesting.org";
        ScimUser idpZoneAdminUser = IntegrationTestUtils.createUser(adminClient, baseUrl, idpZoneAdminEmail, "firstname", "lastname", idpZoneAdminEmail, true);
        IntegrationTestUtils.makeZoneAdmin(identityClient, baseUrl, idpZoneAdminUser.getId(), idpZoneId);
        String idpZoneAdminToken =
            IntegrationTestUtils.getAuthorizationCodeToken(
                serverRunning,
                UaaTestAccounts.standard(serverRunning),
                "identity",
                "identitysecret",
                idpZoneAdminEmail,
                "secr3T"
            );

        String idpZoneUserEmail = new RandomValueStringGenerator().generate() + "@samltesting.org";
        String idpZoneUrl = baseUrl.replace("localhost", idpZoneId + ".localhost");
        createZoneUser(idpZoneId, idpZoneAdminToken, idpZoneUserEmail, idpZoneUrl);

        SamlConfig samlConfig = new SamlConfig();
        samlConfig.setWantAssertionSigned(true);
        samlConfig.addAndActivateKey("key-1", new SamlKey(key1, passphrase1, certificate1));
        samlConfig.addKey("key-2", new SamlKey(key2, passphrase2, certificate2));

        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setSamlConfig(samlConfig);
        IdentityZone spZone = IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, spZoneId, spZoneId, config);
        assertEquals(2, spZone.getConfig().getSamlConfig().getKeys().size());
        assertEquals("key-1", spZone.getConfig().getSamlConfig().getActiveKeyId());

        String spZoneAdminEmail = new RandomValueStringGenerator().generate() + "@samltesting.org";
        ScimUser spZoneAdminUser = IntegrationTestUtils.createUser(
            adminClient,
            baseUrl,
            spZoneAdminEmail,
            "firstname",
            "lastname",
            spZoneAdminEmail,
            true
        );
        IntegrationTestUtils.makeZoneAdmin(identityClient, baseUrl, spZoneAdminUser.getId(), spZoneId);
        String spZoneAdminToken =
            IntegrationTestUtils.getAuthorizationCodeToken(
                serverRunning,
                UaaTestAccounts.standard(serverRunning),
                "identity",
                "identitysecret",
                spZoneAdminEmail,
                "secr3T"
            );
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

        performLogin(idpZoneId, idpZoneUserEmail, idpZoneUrl, spZone, spZoneUrl, samlIdentityProviderDefinition);

        //change the active key
        spZone.getConfig().getSamlConfig().setActiveKeyId("key-2");
        spZone = IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, spZoneId, spZoneId, spZone.getConfig());
        assertEquals(2, spZone.getConfig().getSamlConfig().getKeys().size());
        assertEquals("key-2", spZone.getConfig().getSamlConfig().getActiveKeyId());
        performLogin(idpZoneId, idpZoneUserEmail, idpZoneUrl, spZone, spZoneUrl, samlIdentityProviderDefinition);

        //remove the inactive key
        spZone.getConfig().getSamlConfig().removeKey("key-1");
        spZone = IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, spZoneId, spZoneId, spZone.getConfig());
        assertEquals(1, spZone.getConfig().getSamlConfig().getKeys().size());
        assertEquals("key-2", spZone.getConfig().getSamlConfig().getActiveKeyId());
        performLogin(idpZoneId, idpZoneUserEmail, idpZoneUrl, spZone, spZoneUrl, samlIdentityProviderDefinition);

        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(spZoneUrl + "/logout.do");

        // disable the provider
        idp.setActive(false);
        idp = IntegrationTestUtils.createOrUpdateProvider(spZoneAdminToken, baseUrl, idp);
        assertNotNull(idp.getId());
        webDriver.get(spZoneUrl + "/login");
        assertEquals(spZone.getName(), webDriver.getTitle());
        List<WebElement> elements = webDriver.findElements(By.xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"));
        assertNotNull(elements);
        assertEquals(0, elements.size());

        // enable the provider
        idp.setActive(true);
        idp = IntegrationTestUtils.createOrUpdateProvider(spZoneAdminToken, baseUrl, idp);
        assertNotNull(idp.getId());
        webDriver.get(spZoneUrl + "/login");
        assertEquals(spZone.getName(), webDriver.getTitle());
        elements = webDriver
            .findElements(By.xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"));
        assertNotNull(elements);
        assertEquals(1, elements.size());
    }

    public void performLogin(String idpZoneId, String idpZoneUserEmail, String idpZoneUrl, IdentityZone spZone, String spZoneUrl, SamlIdentityProviderDefinition samlIdentityProviderDefinition) {
            webDriver.get(baseUrl + "/logout.do");
            webDriver.get(spZoneUrl + "/logout.do");
            webDriver.get(idpZoneUrl+ "/logout.do");
            webDriver.get(spZoneUrl + "/");
            assertEquals(spZone.getName(), webDriver.getTitle());
            Cookie beforeLogin = webDriver.manage().getCookieNamed("JSESSIONID");
            assertNotNull(beforeLogin);
            assertNotNull(beforeLogin.getValue());

            List<WebElement> elements = webDriver
                .findElements(By.xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']"));
            assertNotNull(elements);
            assertEquals(1, elements.size());

            WebElement element = elements.get(0);
            assertNotNull(element);

            element.click();
        try {
            webDriver.findElement(By.xpath("//h1[contains(text(), 'Welcome to The Twiglet Zone[" + idpZoneId + "]!')]"));
            webDriver.findElement(By.name("username")).clear();
            webDriver.findElement(By.name("username")).sendKeys(idpZoneUserEmail);
            webDriver.findElement(By.name("password")).sendKeys("secr3T");
            webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
            assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Where to?"));
            Cookie afterLogin = webDriver.manage().getCookieNamed("JSESSIONID");
            assertNotNull(afterLogin);
            assertNotNull(afterLogin.getValue());
            assertNotEquals(beforeLogin.getValue(), afterLogin.getValue());
        } catch (Exception e) {
            Assert.
            assertTrue("Http-Artifact binding is not supported",e instanceof NoSuchElementException);

        }
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
