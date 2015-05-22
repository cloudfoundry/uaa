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

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.lang.RandomStringUtils;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.login.saml.IdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventListener;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.event.IdentityProviderModifiedEvent;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import static java.util.Arrays.asList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class IdentityProviderEndpointsMockMvcTests extends InjectedMockContextTest {
    private TestClient testClient = null;
    private String adminToken;
    private String identityToken;
    private MockMvcUtils mockMvcUtils;
    private TestApplicationEventListener<IdentityProviderModifiedEvent> eventListener;
    private IdentityProviderProvisioning identityProviderProvisioning;

    @Before
    public void setUp() throws Exception {
        testClient = new TestClient(getMockMvc());

        mockMvcUtils = MockMvcUtils.utils();
        eventListener = mockMvcUtils.addEventListener(getWebApplicationContext(), IdentityProviderModifiedEvent.class);

        adminToken = testClient.getClientCredentialsOAuthAccessToken(
            "admin",
            "adminsecret",
            "");
        identityToken = testClient.getClientCredentialsOAuthAccessToken(
            "identity",
            "identitysecret",
            "zones.write");
        identityProviderProvisioning = getWebApplicationContext().getBean(IdentityProviderProvisioning.class);
        eventListener.clearEvents();
    }

    @Test
    public void testCreateAndUpdateIdentityProvider() throws Exception {
        String clientId = RandomStringUtils.randomAlphabetic(6);
        BaseClientDetails client = new BaseClientDetails(clientId,null,"idps.write","password",null);
        client.setClientSecret("test-client-secret");
        mockMvcUtils.createClient(getMockMvc(), adminToken, client);

        ScimUser user = createAdminForZone("idps.write");
        String accessToken = mockMvcUtils.getUserOAuthAccessToken(getMockMvc(), client.getClientId(), client.getClientSecret(), user.getUserName(), "password", "idps.write");

        createAndUpdateIdentityProvider(accessToken, null);
    }

    @Test
    public void testCreateSamlProvider() throws Exception {
        String clientId = RandomStringUtils.randomAlphabetic(6);
        BaseClientDetails client = new BaseClientDetails(clientId,null,"idps.write","password",null);
        client.setClientSecret("test-client-secret");
        mockMvcUtils.createClient(getMockMvc(), adminToken, client);
        ScimUser user = createAdminForZone("idps.write");
        String accessToken = mockMvcUtils.getUserOAuthAccessToken(getMockMvc(), client.getClientId(), client.getClientSecret(), user.getUserName(), "password", "idps.write");

        String origin = "my-saml-provider-"+new RandomValueStringGenerator().generate();
        IdentityProvider provider = new IdentityProvider();
        provider.setActive(true);
        provider.setName(origin);
        provider.setIdentityZoneId(IdentityZone.getUaa().getId());
        provider.setType(Origin.SAML);
        provider.setOriginKey(origin);
        IdentityProviderDefinition samlDefinition = new IdentityProviderDefinition("http://localhost:9999/metadata", null, null, 0, false, true, "Test SAML Provider", null, null);
        provider.setConfig(JsonUtils.writeValueAsString(samlDefinition));

        IdentityProvider created = createIdentityProvider(null, provider, accessToken, status().isCreated());
        assertNotNull(created.getConfig());
        IdentityProviderDefinition samlCreated = created.getConfigValue(IdentityProviderDefinition.class);
        assertEquals(IdentityZone.getUaa().getId(), samlCreated.getZoneId());
        assertEquals(provider.getOriginKey(), samlCreated.getIdpEntityAlias());
    }

    @Test
    public void testEnsureWeRetrieveInactiveIDPsToo() throws Exception {
       testRetrieveIdps(false);
    }

    @Test
    public void testRetrieveOnlyActiveIdps() throws Exception {
        testRetrieveIdps(true);
    }

    private void testRetrieveIdps(boolean retrieveActive) throws Exception {
        String clientId = RandomStringUtils.randomAlphabetic(6);
        BaseClientDetails client = new BaseClientDetails(clientId,null,"idps.write,idps.read","password",null);
        client.setClientSecret("test-client-secret");
        mockMvcUtils.createClient(getMockMvc(), adminToken, client);

        ScimUser user = createAdminForZone("idps.read,idps.write");
        String accessToken = mockMvcUtils.getUserOAuthAccessToken(getMockMvc(), client.getClientId(), client.getClientSecret(), user.getUserName(), "password", "idps.read,idps.write");
        String randomOriginKey = new RandomValueStringGenerator().generate();
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider(randomOriginKey, IdentityZone.getUaa().getId());
        IdentityProvider createdIDP = createIdentityProvider(null, identityProvider, accessToken, status().isCreated());

        String retrieveActiveParam = retrieveActive ? "?active_only=true" : "";
        MockHttpServletRequestBuilder requestBuilder = get("/identity-providers" + retrieveActiveParam)
                .header("Authorization", "Bearer" + accessToken)
                .contentType(APPLICATION_JSON);

        int numberOfIdps = identityProviderProvisioning.retrieveAll(retrieveActive, IdentityZone.getUaa().getId()).size();

        MvcResult result = getMockMvc().perform(requestBuilder).andExpect(status().isOk()).andReturn();
        List<IdentityProvider> identityProviderList = JsonUtils.readValue(result.getResponse().getContentAsString(), new TypeReference<List<IdentityProvider>>() {});
        assertEquals(numberOfIdps, identityProviderList.size());
        assertTrue(identityProviderList.contains(createdIDP));

        createdIDP.setActive(false);
        createdIDP = JsonUtils.readValue(updateIdentityProvider(null, createdIDP, accessToken, status().isOk()).getResponse().getContentAsString(), IdentityProvider.class);

        result = getMockMvc().perform(requestBuilder).andExpect(status().isOk()).andReturn();
        identityProviderList = JsonUtils.readValue(result.getResponse().getContentAsString(), new TypeReference<List<IdentityProvider>>() {
        });
        if (!retrieveActive) {
            assertEquals(numberOfIdps, identityProviderList.size());
            assertTrue(identityProviderList.contains(createdIDP));
        } else {
            assertEquals(numberOfIdps - 1, identityProviderList.size());
            assertFalse(identityProviderList.contains(createdIDP));
        }
    }

    private void createAndUpdateIdentityProvider(String accessToken, String zoneId) throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("testorigin", IdentityZone.getUaa().getId());
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
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("testorigin", IdentityZone.getUaa().getId());
        createIdentityProvider(null, identityProvider, adminToken, status().isForbidden());
        assertEquals(0, eventListener.getEventCount());
    }

    @Test
    public void testUpdateIdentityProviderWithInsufficientScopes() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("testorigin", IdentityZone.getUaa().getId());
        updateIdentityProvider(null, identityProvider, adminToken, status().isForbidden());
        assertEquals(0, eventListener.getEventCount());
    }

    @Test
    public void testCreateAndUpdateIdentityProviderInOtherZone() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("testorigin", IdentityZone.getUaa().getId());
        IdentityZone zone = mockMvcUtils.createZoneUsingWebRequest(getMockMvc(),identityToken);
        ScimUser user = createAdminForZone("zones." + zone.getId() + ".admin");

        String userAccessToken = MockMvcUtils.utils().getUserOAuthAccessTokenAuthCode(getMockMvc(),"identity", "identitysecret", user.getId(), user.getUserName(), "password", "zones." + zone.getId() + ".admin");
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
        BaseClientDetails client = getBaseClientDetails();

        ScimUser user = createAdminForZone("idps.read,idps.write");
        String accessToken = mockMvcUtils.getUserOAuthAccessToken(getMockMvc(), client.getClientId(), client.getClientSecret(), user.getUserName(), "password", "idps.read,idps.write");

        int numberOfIdps = identityProviderProvisioning.retrieveAll(false,IdentityZone.getUaa().getId()).size();

        String originKey = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider newIdp = MultitenancyFixture.identityProvider(originKey, IdentityZone.getUaa().getId());
        newIdp = createIdentityProvider(null, newIdp, accessToken, status().isCreated());

        MockHttpServletRequestBuilder requestBuilder = get("/identity-providers/")
            .header("Authorization", "Bearer" + accessToken)
            .contentType(APPLICATION_JSON);

        MvcResult result = getMockMvc().perform(requestBuilder).andExpect(status().isOk()).andReturn();
        List<IdentityProvider> identityProviderList = JsonUtils.readValue(result.getResponse().getContentAsString(), new TypeReference<List<IdentityProvider>>() {});
        assertEquals(numberOfIdps + 1, identityProviderList.size());
        assertTrue(identityProviderList.contains(newIdp));
    }

    @Test
    public void testListIdpsInOtherZoneFromDefaultZone() throws Exception {
        IdentityZone identityZone = MockMvcUtils.utils().createZoneUsingWebRequest(getMockMvc(), identityToken);
        ScimUser userInDefaultZone = createAdminForZone("zones." + identityZone.getId() + ".admin");
        String zoneAdminToken = MockMvcUtils.utils().getUserOAuthAccessTokenAuthCode(getMockMvc(), "identity", "identitysecret", userInDefaultZone.getId(), userInDefaultZone.getUserName(), "password", "zones." + identityZone.getId() + ".admin");

        IdentityProvider otherZoneIdp = MockMvcUtils.utils().createIdpUsingWebRequest(getMockMvc(), identityZone.getId(), zoneAdminToken, MultitenancyFixture.identityProvider(new RandomValueStringGenerator().generate(), IdentityZone.getUaa().getId()),status().isCreated());

        MockHttpServletRequestBuilder requestBuilder = get("/identity-providers/")
            .header("Authorization", "Bearer" + zoneAdminToken)
            .contentType(APPLICATION_JSON);
        requestBuilder.header(IdentityZoneSwitchingFilter.HEADER, identityZone.getId());

        MvcResult result = getMockMvc().perform(requestBuilder).andExpect(status().isOk()).andReturn();
        List<IdentityProvider> identityProviderList = JsonUtils.readValue(result.getResponse().getContentAsString(), new TypeReference<List<IdentityProvider>>() {
        });
        assertTrue(identityProviderList.contains(otherZoneIdp));
        assertEquals(2, identityProviderList.size());
    }

    @Test
    public void testRetrieveIdpInZone() throws Exception {
        BaseClientDetails client = getBaseClientDetails();

        ScimUser user = createAdminForZone("idps.read,idps.write");
        String accessToken = mockMvcUtils.getUserOAuthAccessToken(getMockMvc(), client.getClientId(), client.getClientSecret(), user.getUserName(), "password", "idps.read,idps.write");

        String originKey = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider newIdp = MultitenancyFixture.identityProvider(originKey, IdentityZone.getUaa().getId());
        newIdp = createIdentityProvider(null, newIdp, accessToken, status().isCreated());

        MockHttpServletRequestBuilder requestBuilder = get("/identity-providers/" + newIdp.getId())
                .header("Authorization", "Bearer" + accessToken)
                .contentType(APPLICATION_JSON);

        MvcResult result = getMockMvc().perform(requestBuilder).andExpect(status().isOk()).andReturn();
        IdentityProvider retrieved = JsonUtils.readValue(result.getResponse().getContentAsString(), IdentityProvider.class);
        assertEquals(newIdp, retrieved);
    }

    @Test
    public void testRetrieveIdpInZoneWithInsufficientScopes() throws Exception {
        BaseClientDetails client = getBaseClientDetails();

        ScimUser user = createAdminForZone("idps.write");
        String accessToken = mockMvcUtils.getUserOAuthAccessToken(getMockMvc(), client.getClientId(), client.getClientSecret(), user.getUserName(), "password", "idps.write");

        String originKey = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider newIdp = MultitenancyFixture.identityProvider(originKey, IdentityZone.getUaa().getId());
        newIdp = createIdentityProvider(null, newIdp, accessToken, status().isCreated());

        MockHttpServletRequestBuilder requestBuilder = get("/identity-providers/" + newIdp.getId())
                .header("Authorization", "Bearer" + adminToken)
                .contentType(APPLICATION_JSON);

        getMockMvc().perform(requestBuilder).andExpect(status().isForbidden());
    }

    @Test
    public void testListIdpsWithInsufficientScopes() throws Exception {
        MockHttpServletRequestBuilder requestBuilder = get("/identity-providers/")
            .header("Authorization", "Bearer" + adminToken)
            .contentType(APPLICATION_JSON);
        getMockMvc().perform(requestBuilder).andExpect(status().isForbidden()).andReturn();

    }

    private BaseClientDetails getBaseClientDetails() throws Exception {
        String clientId = RandomStringUtils.randomAlphabetic(6);
        BaseClientDetails client = new BaseClientDetails(clientId,null,"idps.read,idps.write","password",null);
        client.setClientSecret("test-client-secret");
        mockMvcUtils.createClient(getMockMvc(), adminToken, client);
        return client;
    }

    private IdentityProvider createIdentityProvider(String zoneId, IdentityProvider identityProvider, String token, ResultMatcher resultMatcher) throws Exception {
        return mockMvcUtils.createIdpUsingWebRequest(getMockMvc(), zoneId, token, identityProvider, resultMatcher);
    }

    private MvcResult updateIdentityProvider(String zoneId, IdentityProvider identityProvider, String token, ResultMatcher resultMatcher) throws Exception {
        MockHttpServletRequestBuilder requestBuilder = put("/identity-providers/"+identityProvider.getId())
            .header("Authorization", "Bearer" + token)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(identityProvider));
        if (zoneId != null) {
            requestBuilder.header(IdentityZoneSwitchingFilter.HEADER, zoneId);
        }

        MvcResult result = getMockMvc().perform(requestBuilder)
            .andExpect(resultMatcher)
            .andReturn();
        return result;
    }

    private ScimUser createAdminForZone(String scopes) throws Exception {
        String random = RandomStringUtils.randomAlphabetic(6);
        ScimUser user = new ScimUser();
        user.setUserName(random + "@example.com");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue(random + "@example.com");
        user.setEmails(asList(email));
        user.setPassword("password");
        ScimUser createdUser = mockMvcUtils.createUser(getMockMvc(), adminToken, user);

        // Create the zones.<zone_id>.admin Group
        // Add User to the zones.<zone_id>.admin Group
        for (String scope : StringUtils.commaDelimitedListToSet(scopes)) {
            ScimGroup group = mockMvcUtils.getGroup(getMockMvc(), adminToken, scope);
            if (group==null) {
                group = new ScimGroup(scope);
                group.setMembers(Arrays.asList(new ScimGroupMember(createdUser.getId())));
                mockMvcUtils.createGroup(getMockMvc(), adminToken, group);
            } else {
                List<ScimGroupMember> members = new LinkedList(group.getMembers());
                members.add(new ScimGroupMember(createdUser.getId()));
                group.setMembers(members);
                mockMvcUtils.updateGroup(getMockMvc(), adminToken, group);
            }
        }
        return createdUser;
    }
}
