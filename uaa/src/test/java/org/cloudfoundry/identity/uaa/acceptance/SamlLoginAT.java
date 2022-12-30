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
package org.cloudfoundry.identity.uaa.acceptance;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.io.FileUtils;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.feature.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.integration.feature.TestClient;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.integration.util.ScreenshotOnFail;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.hamcrest.Matchers;
import org.junit.*;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.opensaml.xml.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.io.File;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.test.context.TestExecutionListeners.MergeMode.MERGE_WITH_DEFAULTS;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
@TestExecutionListeners(value = { ScreenshotOnFail.class }, mergeMode = MERGE_WITH_DEFAULTS)
public class SamlLoginAT {

    private static final String SAML_ENTITY_ID = "gefssprd";

    @Autowired
    RestOperations restOperations;

    @Autowired
    WebDriver webDriver;
    
    protected final static Logger logger = LoggerFactory.getLogger(SamlLoginAT.class);

    @Value("${ACCEPTANCE_ZONE_URL:}")
    String baseUrl;

    @Value("${ACCEPTANCE_ZONE_ID:uaa-acceptance-zone}")
    String acceptanceZoneId;
    
    @Value("${SAML_IDP_USER}")
    String GESSOUsername;
    
    @Value("${SAML_IDP_USER_PW}")
    String GESSOPassword;

    @Autowired
    TestAccounts testAccounts;

    @Autowired
    TestClient testClient;
    
    String zoneAdminToken;

    private static SamlTestUtils samlTestUtils;

    @BeforeClass
    public static void setupSamlUtils() throws Exception {
        samlTestUtils = new SamlTestUtils();
        try {
            samlTestUtils.initialize();
        } catch (ConfigurationException e) {
            samlTestUtils.initializeSimple();
        }
    }

    public static String getValidRandomIDPMetaData() {
        return String.format(MockMvcUtils.IDP_META_DATA, new RandomValueStringGenerator().generate());
    }

    @Before
    public void clearWebDriverOfCookies() throws Exception {
        this.zoneAdminToken = IntegrationTestUtils.getClientCredentialsToken(this.baseUrl, "admin", "acceptance-test");
    }

    @Test
    public void testGESSOLogin() throws Exception {
        Long beforeTest = System.currentTimeMillis();
        testGESSOLogin("/login", "You should not see this page. Set up your redirect URI.");
        Long afterTest = System.currentTimeMillis();
        ScimUser user = IntegrationTestUtils.getUser(this.zoneAdminToken, this.baseUrl, SAML_ENTITY_ID, this.GESSOUsername);
        IntegrationTestUtils.validateUserLastLogon(user, beforeTest, afterTest);
    }

    private void testGESSOLogin(String firstUrl, String lookfor) throws Exception {
        Assert.assertTrue("Expected acceptance zone subdomain to exist", findZoneInUaa());

        IdentityProvider<SamlIdentityProviderDefinition> provider = createGESSOIdentityProvider(SAML_ENTITY_ID);
        this.webDriver.get(this.baseUrl + firstUrl);
        this.webDriver.findElement(By.xpath("//a[text()='" + provider.getConfig().getLinkText() + "']")).click();

        assertEquals("GE Single Sign On", this.webDriver.getTitle());
        this.webDriver.findElement(By.id("identifierInput")).clear();
        this.webDriver.findElement(By.id("identifierInput")).sendKeys(this.GESSOUsername);
        this.webDriver.findElement(By.id("post-button")).click();

        assertEquals(this.GESSOUsername, this.webDriver.findElement(By.id("username")).getAttribute("value"));
        this.webDriver.findElement(By.id("password")).sendKeys(this.GESSOPassword);
        this.webDriver.findElement(By.id("shared-computer-login-button")).click();

        assertThat(this.webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString(lookfor));
    }

    private boolean findZoneInUaa() {
        RestTemplate zoneAdminClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(this.baseUrl, new String[0], "admin", "acceptance-test"));
        ResponseEntity<String> responseEntity = zoneAdminClient.getForEntity(this.baseUrl + "/login", String.class);

        logger.info("response body: " + responseEntity.getStatusCode());
        return responseEntity.getStatusCode() == HttpStatus.OK;
    }

    protected IdentityProvider<SamlIdentityProviderDefinition> createGESSOIdentityProvider(String originKey) throws Exception {
        SamlIdentityProviderDefinition geSSOIdentityProviderDefinition = createGESSOIDPDefinition(originKey);
        geSSOIdentityProviderDefinition.setAddShadowUserOnLogin(true);
        IdentityProvider provider = new IdentityProvider();
        provider.setIdentityZoneId(this.acceptanceZoneId);
        provider.setType(OriginKeys.SAML);
        provider.setActive(true);
        provider.setConfig(geSSOIdentityProviderDefinition);
        provider.setOriginKey(geSSOIdentityProviderDefinition.getIdpEntityAlias());
        provider.setName("GESSO");
        logger.info("our token is: " + this.zoneAdminToken);
        provider = createOrUpdateProvider(this.zoneAdminToken,this.baseUrl,provider);
        assertNotNull(provider.getId());
        return provider;
    }

    public IdentityProvider createOrUpdateProvider(String accessToken,
            String url,
            IdentityProvider provider) {
        logger.info("potential idp: " + provider + " identityzone id: " + provider.getIdentityZoneId());
        RestTemplate client = new RestTemplate();
        MultiValueMap<String,String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer "+accessToken);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        List<IdentityProvider> existing = getProviders(accessToken, url, provider.getIdentityZoneId());
        if (existing!=null) {
            for (IdentityProvider p : existing) {
                logger.info("existing idp: " + p + " identityzone id: " + p.getIdentityZoneId());
                if (p.getOriginKey().equals(provider.getOriginKey()) && p.getIdentityZoneId().equals(provider.getIdentityZoneId())) {
                    provider.setId(p.getId());
                    HttpEntity putHeaders = new HttpEntity(provider, headers);
                    ResponseEntity<String> providerPut = client.exchange(
                            url + "/identity-providers/{id}",
                            HttpMethod.PUT,
                            putHeaders,
                            String.class,
                            provider.getId()
                            );
                    if (providerPut.getStatusCode()==HttpStatus.OK) {
                        return JsonUtils.readValue(providerPut.getBody(), IdentityProvider.class);
                    }
                }
            }
        }

        HttpEntity postHeaders = new HttpEntity(provider, headers);
        ResponseEntity<String> providerPost = client.exchange(
                url + "/identity-providers",
                HttpMethod.POST,
                postHeaders,
                String.class,
                provider.getId()
                );
        if (providerPost.getStatusCode()==HttpStatus.CREATED) {
            return JsonUtils.readValue(providerPost.getBody(), IdentityProvider.class);
        }
        throw new IllegalStateException("Invalid result code returned, unable to create identity provider:"+providerPost.getStatusCode());
    }
    
    public static List<IdentityProvider> getProviders(String zoneAdminToken,
            String url,
            String zoneId) {
        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + zoneAdminToken);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        HttpEntity getHeaders = new HttpEntity(headers);
        ResponseEntity<String> providerGet = client.exchange(
                url + "/identity-providers",
                HttpMethod.GET,
                getHeaders,
                String.class
                );
        if (providerGet != null && providerGet.getStatusCode() == HttpStatus.OK) {
            return JsonUtils.readValue(providerGet.getBody(), new TypeReference<List<IdentityProvider>>() {
            });
        }
        return null;
    }

    private SamlIdentityProviderDefinition createGESSOIDPDefinition(String alias) {
        if (!("gefssstg".equals(alias) || "gefssprd".equals(alias))) {
            throw new IllegalArgumentException("Only valid origins are: gefssstg,gefssprd");
        }
        String metadata = "";
        try {
            metadata = FileUtils.readFileToString(new File("src/test/resources/sso_metadata.xml"));
            logger.info(metadata);
        } catch (Exception e) {
            logger.error("Failed to read the GESSO metadata.", e.getMessage());
        }
        
        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
        def.setZoneId(this.acceptanceZoneId);
        def.setMetaDataLocation(metadata);
        //That's how ge sso rolls in the nameID department
        def.setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
        def.setAssertionConsumerIndex(0);
        def.setMetadataTrustCheck(false);
        def.setShowSamlLink(true);
        def.addAttributeMapping("email", "ssoid");
        def.addAttributeMapping("given_name", "firstname");
        def.addAttributeMapping("family_name", "lastname");
        def.setIdpEntityAlias(alias);
        def.setLinkText("Login with GE SSO("+alias+")");
        return def;
    }

}
