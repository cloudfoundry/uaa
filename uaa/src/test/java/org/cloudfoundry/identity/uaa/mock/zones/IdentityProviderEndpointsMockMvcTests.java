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
import org.cloudfoundry.identity.uaa.zone.IdentityProviderModifiedEvent;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.XmlWebApplicationContext;

import java.util.Arrays;

import static java.util.Arrays.asList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class IdentityProviderEndpointsMockMvcTests {
    private static XmlWebApplicationContext webApplicationContext;
    private static MockMvc mockMvc;
    private static TestClient testClient = null;
    private static String adminToken;
    private static String identityToken;
    private static MockMvcUtils mockMvcUtils;
    private static TestApplicationEventListener<IdentityProviderModifiedEvent> eventListener;

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
    public void testCreateIdentityProvider() throws Exception {
        BaseClientDetails client = new BaseClientDetails("test-client-id",null,"idps.write","password",null);
        client.setClientSecret("test-client-secret");
        mockMvcUtils.createClient(mockMvc, adminToken, client);

        ScimUser user = createAdminForZone("idps.write");
        String accessToken = mockMvcUtils.getUserOAuthAccessToken(mockMvc, client.getClientId(), client.getClientSecret(), user.getUserName(), "password", "idps.write");
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("saml");
        MvcResult result = createIdentityProvider(null, identityProvider, accessToken, status().isCreated());
        IdentityProvider createdIDP = JsonUtils.readValue(result.getResponse().getContentAsString(), IdentityProvider.class);
        assertNotNull(createdIDP.getId());
        assertEquals(identityProvider.getName(), createdIDP.getName());
        assertEquals(identityProvider.getOriginKey(), createdIDP.getOriginKey());
        assertEquals(1, eventListener.getEventCount());
        IdentityProviderModifiedEvent event = eventListener.getLatestEvent();
        assertEquals(AuditEventType.IdentityProviderCreatedEvent, event.getAuditEvent().getType());
    }

    @Test
    public void testCreateIdentityProviderWithInsufficientScopes() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("saml");
        createIdentityProvider(null, identityProvider, adminToken, status().isForbidden());
        assertEquals(0, eventListener.getEventCount());
    }

    @Test
    public void testCreateIdentityProviderInOtherZone() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("saml");
        IdentityZone zone = mockMvcUtils.createZoneUsingWebRequest(mockMvc,identityToken);
        ScimUser user = createAdminForZone("zones." + zone.getId() + ".admin");

        String userAccessToken = testClient.getUserOAuthAccessToken("identity", "identitysecret", user.getUserName(), "password", "zones." + zone.getId() + ".admin");
        eventListener.clearEvents();
        MvcResult result = createIdentityProvider(zone.getId(), identityProvider, userAccessToken, status().isCreated());
        IdentityProvider createdIDP = JsonUtils.readValue(result.getResponse().getContentAsString(), IdentityProvider.class);

        assertNotNull(createdIDP.getId());
        assertEquals(identityProvider.getName(), createdIDP.getName());
        assertEquals(identityProvider.getOriginKey(), createdIDP.getOriginKey());
        assertEquals(1, eventListener.getEventCount());
        IdentityProviderModifiedEvent event = eventListener.getLatestEvent();
        assertEquals(AuditEventType.IdentityProviderCreatedEvent, event.getAuditEvent().getType());

    }

    private MvcResult createIdentityProvider(String zoneId, IdentityProvider identityProvider, String token, ResultMatcher resultMatcher) throws Exception {
        MockHttpServletRequestBuilder requestBuilder = post("/identity-providers/")
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
