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
package org.cloudfoundry.identity.uaa.mock.providers;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.lang.RandomStringUtils;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.impl.config.IdentityProviderBootstrap;
import org.cloudfoundry.identity.uaa.login.Prompt;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.*;
import org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator;
import org.cloudfoundry.identity.uaa.provider.saml.BootstrapSamlIdentityProviderDataTests;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.InMemoryLdapServer;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventListener;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.event.IdentityProviderModifiedEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.StringUtils;
import org.springframework.web.context.WebApplicationContext;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.*;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// TODO: Check to see if the helper methods can be moved to MockMvcUtils
@DefaultTestContext
class IdentityProviderEndpointsMockMvcTests {
    private String adminToken;
    private String identityToken;
    private TestApplicationEventListener<IdentityProviderModifiedEvent> eventListener;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private String lowPrivilegeToken;

    private WebApplicationContext webApplicationContext;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp(
            @Autowired WebApplicationContext webApplicationContext,
            @Autowired ConfigurableApplicationContext configurableApplicationContext,
            @Autowired TestClient testClient,
            @Autowired MockMvc mockMvc) throws Exception {
        this.webApplicationContext = webApplicationContext;
        this.mockMvc = mockMvc;

        eventListener = MockMvcUtils.addEventListener(configurableApplicationContext, IdentityProviderModifiedEvent.class);

        adminToken = testClient.getClientCredentialsOAuthAccessToken(
                "admin",
                "adminsecret",
                "");
        identityToken = testClient.getClientCredentialsOAuthAccessToken(
                "identity",
                "identitysecret",
                "zones.write");

        lowPrivilegeToken = testClient.getClientCredentialsOAuthAccessToken(
                "admin",
                "adminsecret",
                "scim.read");

        identityProviderProvisioning = webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class);
        eventListener.clearEvents();
    }

    @AfterEach
    void clearUaaConfig() {
        webApplicationContext.getBean(JdbcTemplate.class).update("UPDATE identity_provider SET config=null WHERE origin_key='uaa'");
        MockMvcUtils.removeEventListener(webApplicationContext, eventListener);
    }

    // TODO: Do something with these try... catches
    @Test
    void test_delete_through_event() throws Exception {
        String accessToken = setUpAccessToken();
        IdentityProvider idp = createAndUpdateIdentityProvider(accessToken);
        String origin = idp.getOriginKey();
        IdentityProviderBootstrap bootstrap = webApplicationContext.getBean(IdentityProviderBootstrap.class);
        assertNotNull(identityProviderProvisioning.retrieveByOrigin(origin, IdentityZone.getUaaZoneId()));
        try {
            bootstrap.setOriginsToDelete(Collections.singletonList(origin));
            bootstrap.onApplicationEvent(new ContextRefreshedEvent(webApplicationContext));
        } finally {
            bootstrap.setOriginsToDelete(null);
        }
        try {
            identityProviderProvisioning.retrieveByOrigin(origin, IdentityZone.getUaaZoneId());
            fail("Identity provider should have been deleted");
        } catch (EmptyResultDataAccessException ignored) {
        }
    }

    @Test
    void testCreateAndUpdateIdentityProvider() throws Exception {
        String accessToken = setUpAccessToken();
        createAndUpdateIdentityProvider(accessToken);
    }

    @Test
    void testCreateAndUpdateIdentityProviderWithMissingConfig() throws Exception {
        String accessToken = setUpAccessToken();
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("testnoconfig", IdentityZone.getUaaZoneId());
        HashMap identityProviderFields = JsonUtils.convertValue(identityProvider, HashMap.class);

        identityProviderFields.remove("config");

        MvcResult create = mockMvc.perform(post("/identity-providers/")
                .header("Authorization", "Bearer " + accessToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(identityProviderFields)))
                .andExpect(status().isCreated())
                .andReturn();

        identityProvider = JsonUtils.readValue(create.getResponse().getContentAsString(), IdentityProvider.class);

        mockMvc.perform(put("/identity-providers/" + identityProvider.getId())
                .header("Authorization", "Bearer " + accessToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(identityProviderFields)))
                .andExpect(status().isOk());
    }

    @Test
    void test_Create_and_Delete_SamlProvider() throws Exception {
        String origin = "idp-mock-saml-" + new RandomValueStringGenerator().generate();
        String metadata = String.format(BootstrapSamlIdentityProviderDataTests.xmlWithoutID, "http://localhost:9999/metadata/" + origin);
        String accessToken = setUpAccessToken();
        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setActive(true);
        provider.setName(origin);
        provider.setIdentityZoneId(IdentityZone.getUaaZoneId());
        provider.setType(OriginKeys.SAML);
        provider.setOriginKey(origin);
        SamlIdentityProviderDefinition samlDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(metadata)
                .setLinkText("Test SAML Provider");
        samlDefinition.setEmailDomain(Arrays.asList("test.com", "test2.com"));
        List<String> externalGroupsWhitelist = new ArrayList<>();
        externalGroupsWhitelist.add("value");
        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "first_name");
        samlDefinition.setExternalGroupsWhitelist(externalGroupsWhitelist);
        samlDefinition.setAttributeMappings(attributeMappings);

        provider.setConfig(samlDefinition);

        IdentityProvider<SamlIdentityProviderDefinition> created = createIdentityProvider(null, provider, accessToken, status().isCreated());
        assertNotNull(created.getConfig());
        createIdentityProvider(null, created, accessToken, status().isConflict());
        SamlIdentityProviderDefinition samlCreated = created.getConfig();
        assertEquals(Arrays.asList("test.com", "test2.com"), samlCreated.getEmailDomain());
        assertEquals(externalGroupsWhitelist, samlCreated.getExternalGroupsWhitelist());
        assertEquals(attributeMappings, samlCreated.getAttributeMappings());
        assertEquals(IdentityZone.getUaaZoneId(), samlCreated.getZoneId());
        assertEquals(provider.getOriginKey(), samlCreated.getIdpEntityAlias());

        //no access token
        mockMvc.perform(
                delete("/identity-providers/{id}", created.getId())
        ).andExpect(status().isUnauthorized());

        mockMvc.perform(
                delete("/identity-providers/{id}", created.getId())
                        .header("Authorization", "Bearer" + accessToken)
        ).andExpect(status().isOk());

        mockMvc.perform(
                get("/identity-providers/{id}", created.getId())
                        .header("Authorization", "Bearer" + accessToken)
        ).andExpect(status().isNotFound());
    }

    @Test
    void test_delete_with_invalid_id_returns_404() throws Exception {
        String accessToken = setUpAccessToken();
        mockMvc.perform(
                delete("/identity-providers/invalid-id")
                        .header("Authorization", "Bearer" + accessToken)
        ).andExpect(status().isNotFound());
    }

    @Test
    void test_delete_response_not_containing_relying_party_secret() throws Exception {
        BaseClientDetails client = getBaseClientDetails();
        ScimUser user = MockMvcUtils.createAdminForZone(mockMvc, adminToken, "idps.read,idps.write", IdentityZone.getUaaZoneId());
        String accessToken = MockMvcUtils.getUserOAuthAccessToken(mockMvc, client.getClientId(), client.getClientSecret(), user.getUserName(), "secr3T", "idps.read,idps.write");

        String originKey = RandomStringUtils.randomAlphabetic(6);
        OIDCIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();
        definition.setDiscoveryUrl(new URL("https://accounts.google.com/.well-known/openid-configuration"));
        definition.setSkipSslValidation(true);
        definition.setRelyingPartyId("uaa");
        definition.setRelyingPartySecret("secret");
        definition.setShowLinkText(false);
        definition.setUserPropagationParameter("username");
        definition.setExternalGroupsWhitelist(Collections.singletonList("uaa.user"));
        List<Prompt> prompts = Arrays.asList(new Prompt("username", "text", "Email"),
                new Prompt("password", "password", "Password"),
                new Prompt("passcode", "password", "Temporary Authentication Code (Get on at /passcode)"));
        definition.setPrompts(prompts);

        IdentityProvider newIdp = MultitenancyFixture.identityProvider(originKey, IdentityZone.getUaaZoneId());
        newIdp.setConfig(definition);

        IdentityProvider createdIdp = createIdentityProvider(null, newIdp, accessToken, status().isCreated());
        MockHttpServletRequestBuilder requestBuilder = delete("/identity-providers/" + createdIdp.getId())
                .header("Authorization", "Bearer" + accessToken)
                .contentType(APPLICATION_JSON);

        MvcResult result = mockMvc.perform(requestBuilder).andExpect(status().isOk()).andReturn();
        IdentityProvider returnedIdentityProvider = JsonUtils.readValue(
                result.getResponse().getContentAsString(), IdentityProvider.class);
        assertNull(((AbstractExternalOAuthIdentityProviderDefinition)returnedIdentityProvider.getConfig())
                .getRelyingPartySecret());
    }

    @Test
    void test_delete_response_not_containing_bind_password() throws Exception {
        BaseClientDetails client = getBaseClientDetails();
        MockMvcUtils.IdentityZoneCreationResult zone =
                MockMvcUtils.createOtherIdentityZoneAndReturnResult(
                        "my-sub-domain", mockMvc, webApplicationContext,
                        client, IdentityZoneHolder.getCurrentZoneId());

        IdentityProvider newIdp = MultitenancyFixture.identityProvider(
                OriginKeys.LDAP, "");
        newIdp.setType(LDAP);
        LdapIdentityProviderDefinition providerDefinition =
                new LdapIdentityProviderDefinition();
        providerDefinition.setLdapProfileFile("ldap/ldap-search-and-compare.xml");
        providerDefinition.setLdapGroupFile("ldap/ldap-groups-as-scopes.xml");
        providerDefinition.setBindUserDn("cn=admin,ou=Users,dc=test,dc=com");
        providerDefinition.setBindPassword("adminsecret");
        providerDefinition.setUserSearchBase("dc=test,dc=com");
        providerDefinition.setUserSearchFilter("cn={0}");
        providerDefinition.setPasswordAttributeName("userPassword");
        providerDefinition.setLocalPasswordCompare(true);
        providerDefinition.setPasswordEncoder(DynamicPasswordComparator.class.getName());
        providerDefinition.setGroupSearchBase("ou=scopes,dc=test,dc=com");
        providerDefinition.setGroupSearchFilter("member={0}");
        providerDefinition.setAutoAddGroups(true);
        providerDefinition.setGroupSearchSubTree(true);
        providerDefinition.setMaxGroupSearchDepth(3);
        providerDefinition.setGroupRoleAttribute("description");

        try (InMemoryLdapServer ldapServer =
                     InMemoryLdapServer.startLdap(33389)) {
            providerDefinition.setBaseUrl(ldapServer.getLdapBaseUrl());
            newIdp.setConfig(providerDefinition);

            // Create an ldap identity provider
            MockHttpServletRequestBuilder createRequestBuilder = post(
                    "/identity-providers")
                    .param("rawConfig", "true")
                    .header(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER,
                            zone.getIdentityZone().getSubdomain())
                    .header("Authorization", "Bearer " + zone.getZoneAdminToken())
                    .contentType(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(newIdp));
            MvcResult createResult = mockMvc.perform(createRequestBuilder)
                    .andExpect(status().isCreated()).andReturn();
            IdentityProvider createdIdp = JsonUtils.readValue(
                    createResult.getResponse().getContentAsString(),
                    IdentityProvider.class);

            // Delete the ldap identity provider and verify that the response
            // does not contain bindPassword
            MockHttpServletRequestBuilder requestBuilder = delete(
                    "/identity-providers/" + createdIdp.getId())
                    .param("rawConfig", "false")
                    .header(IdentityZoneSwitchingFilter.HEADER,
                            zone.getIdentityZone().getId())
                    .header(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER,
                            zone.getIdentityZone().getSubdomain())
                    .header("Authorization", "Bearer " + zone.getZoneAdminToken())
                    .contentType(APPLICATION_JSON);
            MvcResult deleteResult = mockMvc.perform(requestBuilder).andExpect(
                    status().isOk()).andReturn();
            IdentityProvider returnedIdentityProvider = JsonUtils.readValue(
                    deleteResult.getResponse().getContentAsString(),
                    IdentityProvider.class);
            assertNull(((LdapIdentityProviderDefinition)returnedIdentityProvider.
                    getConfig()).getBindPassword());
        }
    }

    @Test
    void testEnsureWeRetrieveInactiveIDPsToo() throws Exception {
        testRetrieveIdps(false);
    }

    @Test
    void testRetrieveOnlyActiveIdps() throws Exception {
        testRetrieveIdps(true);
    }

    @Test
    void testCreateIdentityProviderWithInsufficientScopes() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("testorigin", IdentityZone.getUaaZoneId());
        createIdentityProvider(null, identityProvider, lowPrivilegeToken, status().isForbidden());
        assertEquals(0, eventListener.getEventCount());
    }

    @Test
    void testUpdateIdentityProviderWithInsufficientScopes() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("testorigin", IdentityZone.getUaaZoneId());
        updateIdentityProvider(null, identityProvider, lowPrivilegeToken, status().isForbidden());
        assertEquals(0, eventListener.getEventCount());
    }

    @Test
    void testUpdateUaaIdentityProviderDoesUpdateOfPasswordPolicy() throws Exception {
        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaaZoneId());
        long expireMonths = System.nanoTime() % 100L;
        PasswordPolicy newConfig = new PasswordPolicy(6, 20, 1, 1, 1, 0, (int) expireMonths);
        identityProvider.setConfig(new UaaIdentityProviderDefinition(newConfig, null));
        String accessToken = setUpAccessToken();
        updateIdentityProvider(null, identityProvider, accessToken, status().isOk());
        IdentityProvider modifiedIdentityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaaZoneId());
        assertEquals(newConfig, ((UaaIdentityProviderDefinition) modifiedIdentityProvider.getConfig()).getPasswordPolicy());
    }

    @Test
    void testUpdateUaaIdentityProviderDoesUpdateOfPasswordPolicyWithPasswordNewerThan() throws Exception {
        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaaZoneId());
        long expireMonths = System.nanoTime() % 100L;
        PasswordPolicy newConfig = new PasswordPolicy(6, 20, 1, 1, 1, 0, (int) expireMonths);
        newConfig.setPasswordNewerThan(new Date());
        identityProvider.setConfig(new UaaIdentityProviderDefinition(newConfig, null));
        String accessToken = setUpAccessToken();
        updateIdentityProvider(null, identityProvider, accessToken, status().isOk());
        IdentityProvider modifiedIdentityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaaZoneId());
        assertEquals(newConfig, ((UaaIdentityProviderDefinition) modifiedIdentityProvider.getConfig()).getPasswordPolicy());
    }

    @Test
    void testMalformedPasswordPolicyReturnsUnprocessableEntity() throws Exception {
        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaaZoneId());
        PasswordPolicy policy = new PasswordPolicy().setMinLength(6);
        identityProvider.setConfig(new UaaIdentityProviderDefinition(policy, null));
        String accessToken = setUpAccessToken();
        updateIdentityProvider(null, identityProvider, accessToken, status().isUnprocessableEntity());
    }

    @Test
    void invalid_ldap_origin_returns_UnprocessableEntity() throws Exception {
        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.LDAP, IdentityZone.getUaaZoneId());
        String accessToken = setUpAccessToken();
        updateIdentityProvider(null, identityProvider, accessToken, status().isOk());
        identityProvider.setOriginKey("other");
        updateIdentityProvider(null, identityProvider, accessToken, status().isUnprocessableEntity());
    }

    @Test
    void testCreateAndUpdateIdentityProviderInOtherZone() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("testorigin", IdentityZone.getUaaZoneId());
        IdentityZone zone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityToken);
        ScimUser user = MockMvcUtils.createAdminForZone(mockMvc, adminToken, "zones." + zone.getId() + ".idps.write", IdentityZone.getUaaZoneId());

        String userAccessToken = MockMvcUtils.getUserOAuthAccessTokenAuthCode(mockMvc, "identity", "identitysecret", user.getId(), user.getUserName(), "secr3T", "zones." + zone.getId() + ".idps.write", IdentityZone.getUaaZoneId());
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
    void test_Create_Duplicate_Saml_Identity_Provider_In_Other_Zone() throws Exception {
        String origin1 = "IDPEndpointsMockTests1-" + new RandomValueStringGenerator().generate();
        String origin2 = "IDPEndpointsMockTests2-" + new RandomValueStringGenerator().generate();

        IdentityZone zone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityToken);
        ScimUser user = MockMvcUtils.createAdminForZone(mockMvc, adminToken, "zones." + zone.getId() + ".idps.write", IdentityZone.getUaaZoneId());

        String userAccessToken = MockMvcUtils.getUserOAuthAccessTokenAuthCode(mockMvc, "identity", "identitysecret", user.getId(), user.getUserName(), "secr3T", "zones." + zone.getId() + ".idps.write", IdentityZone.getUaaZoneId());
        eventListener.clearEvents();


        IdentityProvider<SamlIdentityProviderDefinition> identityProvider = MultitenancyFixture.identityProvider(origin1, zone.getId());
        identityProvider.setType(OriginKeys.SAML);

        SamlIdentityProviderDefinition providerDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(String.format(BootstrapSamlIdentityProviderDataTests.xmlWithoutID, "http://www.okta.com/" + identityProvider.getOriginKey()))
                .setIdpEntityAlias(identityProvider.getOriginKey())
                .setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
                .setLinkText("IDPEndpointsMockTests Saml Provider:" + identityProvider.getOriginKey())
                .setZoneId(zone.getId());
        identityProvider.setConfig(providerDefinition);

        IdentityProvider<SamlIdentityProviderDefinition> createdIDP = createIdentityProvider(zone.getId(), identityProvider, userAccessToken, status().isCreated());

        assertNotNull(createdIDP.getId());
        assertEquals(identityProvider.getName(), createdIDP.getName());
        assertEquals(identityProvider.getOriginKey(), createdIDP.getOriginKey());
        assertEquals(identityProvider.getConfig().getIdpEntityAlias(), createdIDP.getConfig().getIdpEntityAlias());
        assertEquals(identityProvider.getConfig().getZoneId(), createdIDP.getConfig().getZoneId());

        identityProvider.setOriginKey(origin2);
        providerDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(providerDefinition.getMetaDataLocation())
                .setIdpEntityAlias(identityProvider.getOriginKey())
                .setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
                .setLinkText("IDPEndpointsMockTests Saml Provider:" + identityProvider.getOriginKey())
                .setZoneId(zone.getId());
        identityProvider.setConfig(providerDefinition);

        createIdentityProvider(zone.getId(), identityProvider, userAccessToken, status().isConflict());
    }

    @Test
    void test_Create_Duplicate_Saml_Identity_Provider_In_Default_Zone() throws Exception {
        String origin1 = "IDPEndpointsMockTests3-" + new RandomValueStringGenerator().generate();
        String origin2 = "IDPEndpointsMockTests4-" + new RandomValueStringGenerator().generate();
        String userAccessToken = setUpAccessToken();

        eventListener.clearEvents();


        IdentityProvider identityProvider = MultitenancyFixture.identityProvider(origin1, IdentityZone.getUaaZoneId());
        identityProvider.setType(OriginKeys.SAML);

        SamlIdentityProviderDefinition providerDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(String.format(BootstrapSamlIdentityProviderDataTests.xmlWithoutID, "http://www.okta.com/" + identityProvider.getOriginKey()))
                .setIdpEntityAlias(identityProvider.getOriginKey())
                .setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
                .setLinkText("IDPEndpointsMockTests Saml Provider:" + identityProvider.getOriginKey())
                .setZoneId(IdentityZone.getUaaZoneId());
        identityProvider.setConfig(providerDefinition);

        IdentityProvider createdIDP = createIdentityProvider(null, identityProvider, userAccessToken, status().isCreated());

        assertNotNull(createdIDP.getId());
        assertEquals(identityProvider.getName(), createdIDP.getName());
        assertEquals(identityProvider.getOriginKey(), createdIDP.getOriginKey());

        identityProvider.setOriginKey(origin2);
        providerDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(providerDefinition.getMetaDataLocation())
                .setIdpEntityAlias(identityProvider.getOriginKey())
                .setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
                .setLinkText("IDPEndpointsMockTests Saml Provider:" + identityProvider.getOriginKey())
                .setZoneId(IdentityZone.getUaaZoneId());
        identityProvider.setConfig(providerDefinition);

        createIdentityProvider(null, identityProvider, userAccessToken, status().isConflict());
    }

    @Test
    void testReadIdentityProviderInOtherZone_Using_Zones_Token() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("testorigin", IdentityZone.getUaaZoneId());
        IdentityZone zone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityToken);

        ScimUser user = MockMvcUtils.createAdminForZone(mockMvc, adminToken, "zones." + zone.getId() + ".idps.write", IdentityZone.getUaaZoneId());
        String userAccessToken = MockMvcUtils.getUserOAuthAccessTokenAuthCode(mockMvc, "identity", "identitysecret", user.getId(), user.getUserName(), "secr3T", "zones." + zone.getId() + ".idps.write", IdentityZone.getUaaZoneId());
        eventListener.clearEvents();
        IdentityProvider createdIDP = createIdentityProvider(zone.getId(), identityProvider, userAccessToken, status().isCreated());

        assertNotNull(createdIDP.getId());
        assertEquals(identityProvider.getName(), createdIDP.getName());
        assertEquals(identityProvider.getOriginKey(), createdIDP.getOriginKey());

        addScopeToIdentityClient("zones.*.idps.read");
        user = MockMvcUtils.createAdminForZone(mockMvc, adminToken, "zones." + zone.getId() + ".idps.read", IdentityZone.getUaaZoneId());
        userAccessToken = MockMvcUtils.getUserOAuthAccessTokenAuthCode(mockMvc, "identity", "identitysecret", user.getId(), user.getUserName(), "secr3T", "zones." + zone.getId() + ".idps.read", IdentityZone.getUaaZoneId());

        MockHttpServletRequestBuilder requestBuilder = get("/identity-providers/" + createdIDP.getId())
                .header("Authorization", "Bearer" + userAccessToken)
                .header(IdentityZoneSwitchingFilter.HEADER, zone.getId())
                .contentType(APPLICATION_JSON);

        MvcResult result = mockMvc.perform(requestBuilder).andExpect(status().isOk()).andReturn();
        IdentityProvider retrieved = JsonUtils.readValue(result.getResponse().getContentAsString(), IdentityProvider.class);
        assertEquals(createdIDP, retrieved);
    }

    @Test
    void testListIdpsInZone() throws Exception {
        BaseClientDetails client = getBaseClientDetails();

        ScimUser user = MockMvcUtils.createAdminForZone(mockMvc, adminToken, "idps.read,idps.write", IdentityZone.getUaaZoneId());
        String accessToken = MockMvcUtils.getUserOAuthAccessToken(mockMvc, client.getClientId(), client.getClientSecret(), user.getUserName(), "secr3T", "idps.read,idps.write");

        int numberOfIdps = identityProviderProvisioning.retrieveAll(false, IdentityZone.getUaaZoneId()).size();

        String originKey = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider newIdp = MultitenancyFixture.identityProvider(originKey, IdentityZone.getUaaZoneId());
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
    void testListIdpsInOtherZoneFromDefaultZone() throws Exception {
        IdentityZone identityZone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityToken);
        ScimUser userInDefaultZone = MockMvcUtils.createAdminForZone(mockMvc, adminToken, "zones." + identityZone.getId() + ".idps.read" + ", zones." + identityZone.getId() + ".idps.write", IdentityZone.getUaaZoneId());
        String zoneAdminToken = MockMvcUtils.getUserOAuthAccessTokenAuthCode(mockMvc, "identity", "identitysecret", userInDefaultZone.getId(), userInDefaultZone.getUserName(), "secr3T", "zones." + identityZone.getId() + ".idps.read " + "zones." + identityZone.getId() + ".idps.write", IdentityZone.getUaaZoneId());

        IdentityProvider otherZoneIdp = MockMvcUtils.createIdpUsingWebRequest(mockMvc, identityZone.getId(), zoneAdminToken, MultitenancyFixture.identityProvider(new RandomValueStringGenerator().generate(), IdentityZone.getUaaZoneId()), status().isCreated());

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
    void testRetrieveIdpInZone() throws Exception {
        BaseClientDetails client = getBaseClientDetails();

        ScimUser user = MockMvcUtils.createAdminForZone(mockMvc, adminToken, "idps.read,idps.write", IdentityZone.getUaaZoneId());
        String accessToken = MockMvcUtils.getUserOAuthAccessToken(mockMvc, client.getClientId(), client.getClientSecret(), user.getUserName(), "secr3T", "idps.read,idps.write");

        String originKey = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider newIdp = MultitenancyFixture.identityProvider(originKey, IdentityZone.getUaaZoneId());
        newIdp = createIdentityProvider(null, newIdp, accessToken, status().isCreated());

        MockHttpServletRequestBuilder requestBuilder = get("/identity-providers/" + newIdp.getId())
                .header("Authorization", "Bearer" + accessToken)
                .contentType(APPLICATION_JSON);

        MvcResult result = mockMvc.perform(requestBuilder).andExpect(status().isOk()).andReturn();
        IdentityProvider retrieved = JsonUtils.readValue(result.getResponse().getContentAsString(), IdentityProvider.class);
        assertEquals(newIdp, retrieved);
    }

    @Test
    void testRetrieveIdpInZoneWithInsufficientScopes() throws Exception {
        BaseClientDetails client = getBaseClientDetails();

        ScimUser user = MockMvcUtils.createAdminForZone(mockMvc, adminToken, "idps.write", IdentityZone.getUaaZoneId());
        String accessToken = MockMvcUtils.getUserOAuthAccessToken(mockMvc, client.getClientId(), client.getClientSecret(), user.getUserName(), "secr3T", "idps.write");

        String originKey = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider newIdp = MultitenancyFixture.identityProvider(originKey, IdentityZone.getUaaZoneId());
        newIdp = createIdentityProvider(null, newIdp, accessToken, status().isCreated());

        MockHttpServletRequestBuilder requestBuilder = get("/identity-providers/" + newIdp.getId())
                .header("Authorization", "Bearer" + lowPrivilegeToken)
                .contentType(APPLICATION_JSON);

        mockMvc.perform(requestBuilder).andExpect(status().isForbidden());
    }

    @Test
    void testListIdpsWithInsufficientScopes() {
        get("/identity-providers/")
                .header("Authorization", "Bearer" + lowPrivilegeToken)
                .contentType(APPLICATION_JSON);

    }

    @Test
    void validateOauthProviderConfigDuringCreate() throws Exception {
        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> identityProvider = getOAuthProviderConfig();
        identityProvider.getConfig().setAuthUrl(null);

        mockMvc.perform(post("/identity-providers")
                .header("Authorization", "bearer " + adminToken)
                .content(JsonUtils.writeValueAsString(identityProvider))
                .contentType(APPLICATION_JSON)
        ).andExpect(status().isUnprocessableEntity());

    }

    @Test
    void validateOauthProviderConfigDuringUpdate() throws Exception {
        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> identityProvider = getOAuthProviderConfig();
        identityProvider.getConfig().setClientAuthInBody(true);
        MvcResult mvcResult = mockMvc.perform(post("/identity-providers")
                .header("Authorization", "bearer " + adminToken)
                .content(JsonUtils.writeValueAsString(identityProvider))
                .contentType(APPLICATION_JSON)
        ).andExpect(status().isCreated()).andReturn();

        String response = mvcResult.getResponse().getContentAsString();
        assertThat(response, not(containsString("relyingPartySecret")));
        identityProvider = JsonUtils.readValue(response, new TypeReference<IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition>>() {
        });
        assertTrue(identityProvider.getConfig().isClientAuthInBody());

        assertTrue(
                ((AbstractExternalOAuthIdentityProviderDefinition) webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class).retrieve(identityProvider.getId(), identityProvider.getIdentityZoneId()).getConfig())
                        .isClientAuthInBody()
        );

        identityProvider.getConfig().setClientAuthInBody(false);

        mvcResult = mockMvc.perform(put("/identity-providers/" + identityProvider.getId())
                .header("Authorization", "bearer " + adminToken)
                .content(JsonUtils.writeValueAsString(identityProvider))
                .contentType(APPLICATION_JSON)
        ).andExpect(status().isOk()).andReturn();
        response = mvcResult.getResponse().getContentAsString();
        assertThat(response, not(containsString("relyingPartySecret")));
        identityProvider = JsonUtils.readValue(response, new TypeReference<IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition>>() {
        });
        assertFalse(identityProvider.getConfig().isClientAuthInBody());
        assertFalse(
                ((AbstractExternalOAuthIdentityProviderDefinition) webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class).retrieve(identityProvider.getId(), identityProvider.getIdentityZoneId()).getConfig())
                        .isClientAuthInBody()
        );

        identityProvider.getConfig().setTokenUrl(null);


        mockMvc.perform(put("/identity-providers/" + identityProvider.getId())
                .header("Authorization", "bearer " + adminToken)
                .content(JsonUtils.writeValueAsString(identityProvider))
                .contentType(APPLICATION_JSON)
        ).andExpect(status().isUnprocessableEntity());
    }

    @Test
    void testUpdatePasswordPolicyWithPasswordNewerThan() throws Exception {
        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaaZoneId());
        identityProvider.setConfig(new UaaIdentityProviderDefinition(new PasswordPolicy(0, 20, 0, 0, 0, 0, 0), null));
        identityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());
        IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
        identityProviderStatus.setRequirePasswordChange(true);
        String accessToken = setUpAccessToken();
        MvcResult mvcResult = mockMvc.perform(patch("/identity-providers/" + identityProvider.getId() + "/status")
                .header("Authorization", "Bearer " + accessToken)
                .content(JsonUtils.writeValueAsString(identityProviderStatus))
                .contentType(APPLICATION_JSON)
        ).andExpect(status().isOk()).andReturn();

        IdentityProviderStatus updatedStatus = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), IdentityProviderStatus.class);
        assertEquals(identityProviderStatus.getRequirePasswordChange(), updatedStatus.getRequirePasswordChange());
    }

    private IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> getOAuthProviderConfig() throws MalformedURLException {
        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> identityProvider = new IdentityProvider<>();
        identityProvider.setName("my oidc provider");
        identityProvider.setIdentityZoneId(OriginKeys.UAA);
        OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition();
        config.addAttributeMapping(USER_NAME_ATTRIBUTE_NAME, "user_name");
        config.setAuthUrl(new URL("http://oidc10.uaa.com/oauth/authorize"));
        config.setTokenUrl(new URL("http://oidc10.uaa.com/oauth/token"));
        config.setTokenKeyUrl(new URL("http://oidc10.uaa.com/token_key"));
        config.setShowLinkText(true);
        config.setLinkText("My OIDC Provider");
        config.setSkipSslValidation(true);
        config.setRelyingPartyId("identity");
        config.setRelyingPartySecret("identitysecret");
        identityProvider.setConfig(config);
        identityProvider.setOriginKey("puppy");
        return identityProvider;
    }

    private BaseClientDetails getBaseClientDetails() throws Exception {
        String clientId = RandomStringUtils.randomAlphabetic(6);
        BaseClientDetails client = new BaseClientDetails(clientId, null, "idps.read,idps.write", "password", null);
        client.setClientSecret("test-client-secret");
        MockMvcUtils.createClient(mockMvc, adminToken, client);
        return client;
    }

    private IdentityProvider createIdentityProvider(String zoneId, IdentityProvider identityProvider, String token, ResultMatcher resultMatcher) throws Exception {
        return MockMvcUtils.createIdpUsingWebRequest(mockMvc, zoneId, token, identityProvider, resultMatcher);
    }

    private MvcResult updateIdentityProvider(String zoneId, IdentityProvider identityProvider, String token, ResultMatcher resultMatcher) throws Exception {
        MockHttpServletRequestBuilder requestBuilder = put("/identity-providers/" + identityProvider.getId())
                .header("Authorization", "Bearer" + token)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(identityProvider));
        if (zoneId != null) {
            requestBuilder.header(IdentityZoneSwitchingFilter.HEADER, zoneId);
        }

        return mockMvc.perform(requestBuilder)
                .andExpect(resultMatcher)
                .andReturn();
    }

    private void testRetrieveIdps(boolean retrieveActive) throws Exception {
        String clientId = RandomStringUtils.randomAlphabetic(6);
        BaseClientDetails client = new BaseClientDetails(clientId, null, "idps.write,idps.read", "password", null);
        client.setClientSecret("test-client-secret");
        MockMvcUtils.createClient(mockMvc, adminToken, client);

        ScimUser user = MockMvcUtils.createAdminForZone(mockMvc, adminToken, "idps.read,idps.write", IdentityZone.getUaaZoneId());
        String accessToken = MockMvcUtils.getUserOAuthAccessToken(mockMvc, client.getClientId(), client.getClientSecret(), user.getUserName(), "secr3T", "idps.read,idps.write");
        String randomOriginKey = new RandomValueStringGenerator().generate();
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider(randomOriginKey, IdentityZone.getUaaZoneId());
        IdentityProvider createdIDP = createIdentityProvider(null, identityProvider, accessToken, status().isCreated());

        String retrieveActiveParam = retrieveActive ? "?active_only=true" : "";
        MockHttpServletRequestBuilder requestBuilder = get("/identity-providers" + retrieveActiveParam)
                .header("Authorization", "Bearer" + accessToken)
                .contentType(APPLICATION_JSON);

        int numberOfIdps = identityProviderProvisioning.retrieveAll(retrieveActive, IdentityZone.getUaaZoneId()).size();

        MvcResult result = mockMvc.perform(requestBuilder).andExpect(status().isOk()).andReturn();
        List<IdentityProvider> identityProviderList = JsonUtils.readValue(result.getResponse().getContentAsString(), new TypeReference<List<IdentityProvider>>() {
        });
        assertEquals(numberOfIdps, identityProviderList.size());
        assertTrue(identityProviderList.contains(createdIDP));

        createdIDP.setActive(false);
        createdIDP = JsonUtils.readValue(updateIdentityProvider(null, createdIDP, accessToken, status().isOk()).getResponse().getContentAsString(), IdentityProvider.class);

        result = mockMvc.perform(requestBuilder).andExpect(status().isOk()).andReturn();
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

    private IdentityProvider createAndUpdateIdentityProvider(String accessToken) throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("testorigin", IdentityZone.getUaaZoneId());
        // create
        // check response
        IdentityProvider createdIDP = createIdentityProvider(null, identityProvider, accessToken, status().isCreated());
        assertNotNull(createdIDP.getId());
        assertEquals(identityProvider.getName(), createdIDP.getName());
        assertEquals(identityProvider.getOriginKey(), createdIDP.getOriginKey());

        // check audit
        assertEquals(1, eventListener.getEventCount());
        IdentityProviderModifiedEvent event = eventListener.getLatestEvent();
        assertEquals(AuditEventType.IdentityProviderCreatedEvent, event.getAuditEvent().getType());

        // check db
        IdentityProvider persisted = identityProviderProvisioning.retrieve(createdIDP.getId(), createdIDP.getIdentityZoneId());
        assertNotNull(persisted.getId());
        assertEquals(identityProvider.getName(), persisted.getName());
        assertEquals(identityProvider.getOriginKey(), persisted.getOriginKey());

        // update
//        String newConfig = RandomStringUtils.randomAlphanumeric(1024);
        createdIDP.setConfig(new UaaIdentityProviderDefinition(null, null));
        updateIdentityProvider(null, createdIDP, accessToken, status().isOk());

        // check db
        persisted = identityProviderProvisioning.retrieve(createdIDP.getId(), createdIDP.getIdentityZoneId());
        assertEquals(createdIDP.getId(), persisted.getId());
        assertEquals(createdIDP.getName(), persisted.getName());
        assertEquals(createdIDP.getOriginKey(), persisted.getOriginKey());
        assertEquals(createdIDP.getConfig(), persisted.getConfig());

        // check audit
        assertEquals(2, eventListener.getEventCount());
        event = eventListener.getLatestEvent();
        assertEquals(AuditEventType.IdentityProviderModifiedEvent, event.getAuditEvent().getType());

        return identityProvider;
    }

    private void addScopeToIdentityClient(String scope) {
        JdbcTemplate template = webApplicationContext.getBean(JdbcTemplate.class);
        String scopes = template.queryForObject("select scope from oauth_client_details where identity_zone_id='uaa' and client_id='identity'", String.class);
        boolean update = false;
        if (!StringUtils.hasText(scopes)) {
            scopes = scope;
            update = true;
        } else if (!scopes.contains(scope)) {
            scopes = scopes + "," + scope;
            update = true;
        }
        if (update) {
            assertEquals(1, template.update("UPDATE oauth_client_details SET scope=? WHERE identity_zone_id='uaa' AND client_id='identity'", scopes));
        }
    }

    private String setUpAccessToken() throws Exception {
        String clientId = RandomStringUtils.randomAlphabetic(6);
        BaseClientDetails client = new BaseClientDetails(clientId, null, "idps.read,idps.write", "password", null);
        client.setClientSecret("test-client-secret");
        MockMvcUtils.createClient(mockMvc, adminToken, client);

        ScimUser user = MockMvcUtils.createAdminForZone(mockMvc, adminToken, "idps.write,idps.read", IdentityZone.getUaaZoneId());
        return MockMvcUtils.getUserOAuthAccessToken(mockMvc, client.getClientId(), client.getClientSecret(), user.getUserName(), "secr3T", "idps.read idps.write");
    }
}
