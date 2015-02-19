/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.mock.zones;

import com.googlecode.flyway.core.Flyway;

import org.apache.commons.lang.RandomStringUtils;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventListener;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.event.IdentityProviderModifiedEvent;
import org.codehaus.jackson.type.TypeReference;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.XmlWebApplicationContext;

import java.util.Arrays;
import java.util.List;

import static java.util.Arrays.asList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class IdentityProviderEndpointsMockMvcTests {
    private static XmlWebApplicationContext webApplicationContext;
    private static MockMvc mockMvc;
    private static TestClient testClient = null;
    private static String adminToken;
    private static String identityToken;
    private static MockMvcUtils mockMvcUtils;
    private static TestApplicationEventListener<IdentityProviderModifiedEvent> eventListener;
    private static IdentityProviderProvisioning identityProviderProvisioning;

    @BeforeClass
    public static void setUp() throws Exception {
        webApplicationContext = new XmlWebApplicationContext();
        webApplicationContext.setServletContext(new MockServletContext());
        new YamlServletProfileInitializerContextInitializer().initializeContext(webApplicationContext, "uaa.yml,login.yml");
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        webApplicationContext.refresh();
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);

        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).addFilter(springSecurityFilterChain)
            .build();
        testClient = new TestClient(mockMvc);

        eventListener = TestApplicationEventListener.forEventClass(IdentityProviderModifiedEvent.class);
        webApplicationContext.addApplicationListener(eventListener);

        adminToken = testClient.getClientCredentialsOAuthAccessToken(
            "admin",
            "adminsecret",
            "");
        identityToken = testClient.getClientCredentialsOAuthAccessToken(
            "identity",
            "identitysecret",
            "zones.create");
        mockMvcUtils = MockMvcUtils.utils();
        identityProviderProvisioning = webApplicationContext.getBean(IdentityProviderProvisioning.class);
    }
    
    @Before
    public void before() {
        eventListener.clearEvents();
    }

    @AfterClass
    public static void tearDown() throws Exception {
        Flyway flyway = webApplicationContext.getBean(Flyway.class);
        flyway.clean();
        webApplicationContext.close();
    }

    @Test
    public void testCreateAndUpdateIdentityProvider() throws Exception {
        String clientId = RandomStringUtils.randomAlphabetic(6);
        BaseClientDetails client = new BaseClientDetails(clientId,null,"idps.write","password",null);
        client.setClientSecret("test-client-secret");
        mockMvcUtils.createClient(mockMvc, adminToken, client);

        ScimUser user = createAdminForZone("idps.write");
        String accessToken = mockMvcUtils.getUserOAuthAccessToken(mockMvc, client.getClientId(), client.getClientSecret(), user.getUserName(), "password", "idps.write");
        
        createAndUpdateIdentityProvider(accessToken,  null);
    }

    private void createAndUpdateIdentityProvider(String accessToken, String zoneId) throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("saml");
        // create
        // check response
        IdentityProvider createdIDP = createIdentityProvider(zoneId, identityProvider, accessToken, status().isCreated());
        assertNotNull(createdIDP.getId());
        assertEquals(identityProvider.getName(), createdIDP.getName());
        assertEquals(identityProvider.getOriginKey(), createdIDP.getOriginKey());
        
        // check audit
        assertEquals(1, eventListener.getEventCount());
        IdentityProviderModifiedEvent event = eventListener.getLatestEvent();
        assertEquals(AuditEventType.IdentityProviderCreatedEvent, event.getAuditEvent().getType());
        
        // check db
        IdentityProvider persisted = identityProviderProvisioning.retrieve(createdIDP.getId());
        assertNotNull(persisted.getId());
        assertEquals(identityProvider.getName(), persisted.getName());
        assertEquals(identityProvider.getOriginKey(), persisted.getOriginKey());
        
        // update
        String newConfig = RandomStringUtils.randomAlphanumeric(1024);
        createdIDP.setConfig(newConfig);
        updateIdentityProvider(null, createdIDP, accessToken, status().isOk());
        
        // check db
        persisted = identityProviderProvisioning.retrieve(createdIDP.getId());
        assertEquals(newConfig, persisted.getConfig());
        assertEquals(createdIDP.getId(), persisted.getId());
        assertEquals(createdIDP.getName(), persisted.getName());
        assertEquals(createdIDP.getOriginKey(), persisted.getOriginKey());
        
        // check audit
        assertEquals(2, eventListener.getEventCount());
        event = eventListener.getLatestEvent();
        assertEquals(AuditEventType.IdentityProviderModifiedEvent, event.getAuditEvent().getType());
    }
    
    @Test
    public void testCreateIdentityProviderWithInsufficientScopes() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("saml");
        createIdentityProvider(null, identityProvider, adminToken, status().isForbidden());
        assertEquals(0, eventListener.getEventCount());
    }
    
    @Test
    public void testUpdateIdentityProviderWithInsufficientScopes() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("saml");
        updateIdentityProvider(null, identityProvider, adminToken, status().isForbidden());
        assertEquals(0, eventListener.getEventCount());
    }

    @Test
    public void testCreateAndUpdateIdentityProviderInOtherZone() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("saml");
        IdentityZone zone = mockMvcUtils.createZoneUsingWebRequest(mockMvc,identityToken);
        ScimUser user = createAdminForZone("zones." + zone.getId() + ".admin");

        String userAccessToken = MockMvcUtils.utils().getUserOAuthAccessTokenAuthCode(mockMvc,"identity", "identitysecret", user.getId(), user.getUserName(), "password", "zones." + zone.getId() + ".admin");
        eventListener.clearEvents();
        IdentityProvider createdIDP = createIdentityProvider(zone.getId(), identityProvider, userAccessToken, status().isCreated());


        assertNotNull(createdIDP.getId());
        assertEquals(identityProvider.getName(), createdIDP.getName());
        assertEquals(identityProvider.getOriginKey(), createdIDP.getOriginKey());
        assertEquals(1, eventListener.getEventCount());
        IdentityProviderModifiedEvent event = eventListener.getLatestEvent();
        assertEquals(AuditEventType.IdentityProviderCreatedEvent, event.getAuditEvent().getType());
    }

    @Test
    public void testListIdpsInZone() throws Exception {
        String clientId = RandomStringUtils.randomAlphabetic(6);
        BaseClientDetails client = new BaseClientDetails(clientId,null,"idps.read,idps.write","password",null);
        client.setClientSecret("test-client-secret");
        mockMvcUtils.createClient(mockMvc, adminToken, client);

        ScimUser user = createAdminForZone("idps.read,idps.write");
        String accessToken = mockMvcUtils.getUserOAuthAccessToken(mockMvc, client.getClientId(), client.getClientSecret(), user.getUserName(), "password", "idps.read,idps.write");

        int numberOfIdps = identityProviderProvisioning.retrieveAll().size();

        String originKey = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider newIdp = MultitenancyFixture.identityProvider(originKey);
        newIdp = createIdentityProvider(null, newIdp, accessToken, status().isCreated());

        MockHttpServletRequestBuilder requestBuilder = get("/identity-providers/")
            .header("Authorization", "Bearer" + accessToken)
            .contentType(APPLICATION_JSON);

        MvcResult result = mockMvc.perform(requestBuilder).andExpect(status().isOk()).andReturn();
        List<IdentityProvider> identityProviderList = JsonUtils.readValue(result.getResponse().getContentAsString(), new TypeReference<List<IdentityProvider>>() {
        });
        assertEquals(numberOfIdps + 1, identityProviderList.size());
        assertTrue(identityProviderList.contains(newIdp));
    }

    @Test
    public void testListIdpsInOtherZoneFromDefaultZone() throws Exception {
        IdentityZone identityZone = MockMvcUtils.utils().createZoneUsingWebRequest(mockMvc, identityToken);
        ScimUser userInDefaultZone = createAdminForZone("zones." + identityZone.getId() + ".admin");
        String zoneAdminToken = MockMvcUtils.utils().getUserOAuthAccessTokenAuthCode(mockMvc, "identity", "identitysecret", userInDefaultZone.getId(), userInDefaultZone.getUserName(), "password", "zones." + identityZone.getId() + ".admin");

        IdentityProvider otherZoneIdp = MockMvcUtils.utils().createIdpUsingWebRequest(mockMvc, identityZone.getId(), zoneAdminToken, MultitenancyFixture.identityProvider(new RandomValueStringGenerator().generate()),status().isCreated());

        MockHttpServletRequestBuilder requestBuilder = get("/identity-providers/")
            .header("Authorization", "Bearer" + zoneAdminToken)
            .contentType(APPLICATION_JSON);
        requestBuilder.header(IdentityZoneSwitchingFilter.HEADER, identityZone.getId());

        MvcResult result = mockMvc.perform(requestBuilder).andExpect(status().isOk()).andReturn();
        List<IdentityProvider> identityProviderList = JsonUtils.readValue(result.getResponse().getContentAsString(), new TypeReference<List<IdentityProvider>>() {
        });
        assertTrue(identityProviderList.contains(otherZoneIdp));
        assertEquals(2, identityProviderList.size());
    }

    @Test
    public void testListIdpsWithInsufficientScopes() throws Exception {
        MockHttpServletRequestBuilder requestBuilder = get("/identity-providers/")
            .header("Authorization", "Bearer" + adminToken)
            .contentType(APPLICATION_JSON);
        mockMvc.perform(requestBuilder).andExpect(status().isForbidden()).andReturn();

    }

    private IdentityProvider createIdentityProvider(String zoneId, IdentityProvider identityProvider, String token, ResultMatcher resultMatcher) throws Exception {
        return mockMvcUtils.createIdpUsingWebRequest(mockMvc, zoneId, token, identityProvider, resultMatcher);
    }
    
    private MvcResult updateIdentityProvider(String zoneId, IdentityProvider identityProvider, String token, ResultMatcher resultMatcher) throws Exception {
        MockHttpServletRequestBuilder requestBuilder = put("/identity-providers/"+identityProvider.getId())
            .header("Authorization", "Bearer" + token)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(identityProvider));
        if (zoneId != null) {
            requestBuilder.header(IdentityZoneSwitchingFilter.HEADER, zoneId);
        }

        MvcResult result = mockMvc.perform(requestBuilder)
            .andExpect(resultMatcher)
            .andReturn();
        return result;
    }

    private ScimUser createAdminForZone(String scope) throws Exception {
        String random = RandomStringUtils.randomAlphabetic(6);
        ScimUser user = new ScimUser();
        user.setUserName(random + "@example.com");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue(random + "@example.com");
        user.setEmails(asList(email));
        user.setPassword("password");
        ScimUser createdUser = mockMvcUtils.createUser(mockMvc, adminToken, user);

        // Create the zones.<zone_id>.admin Group
        // Add User to the zones.<zone_id>.admin Group
        ScimGroup group = new ScimGroup(scope);
        group.setMembers(Arrays.asList(new ScimGroupMember(createdUser.getId())));
        mockMvcUtils.createGroup(mockMvc,adminToken,group);
        return createdUser;
    }
}
