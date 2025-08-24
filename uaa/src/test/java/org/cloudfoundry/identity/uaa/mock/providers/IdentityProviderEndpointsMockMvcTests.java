/*
 * *****************************************************************************
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
import org.apache.commons.lang3.RandomStringUtils;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.impl.config.IdentityProviderBootstrap;
import org.cloudfoundry.identity.uaa.login.Prompt;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderStatus;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
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
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.StringUtils;
import org.springframework.web.context.WebApplicationContext;

import java.net.MalformedURLException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
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

    @Test
    void delete_through_event() throws Exception {
        String accessToken = setUpAccessToken();
        IdentityProvider idp = createAndUpdateIdentityProvider(accessToken);
        String origin = idp.getOriginKey();
        IdentityProviderBootstrap bootstrap = webApplicationContext.getBean(IdentityProviderBootstrap.class);
        assertThat(identityProviderProvisioning.retrieveByOrigin(origin, IdentityZone.getUaaZoneId())).isNotNull();
        try {
            bootstrap.setOriginsToDelete(Collections.singletonList(origin));
            bootstrap.onApplicationEvent(new ContextRefreshedEvent(webApplicationContext));
        } finally {
            bootstrap.setOriginsToDelete(null);
        }
        assertThatThrownBy(() -> identityProviderProvisioning.retrieveByOrigin(origin, IdentityZone.getUaaZoneId()))
                .isInstanceOf(EmptyResultDataAccessException.class);
    }

    @Test
    void testCreateAndUpdateIdentityProvider() throws Exception {
        String accessToken = setUpAccessToken();
        createAndUpdateIdentityProvider(accessToken);
    }

    @Test
    void createAndUpdateIdentityProviderWithMissingConfig() throws Exception {
        String accessToken = setUpAccessToken();
        IdentityProvider<AbstractIdentityProviderDefinition> identityProvider = MultitenancyFixture.identityProvider("testnoconfig", IdentityZone.getUaaZoneId());
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
    void create_and_delete_saml_provider() throws Exception {
        String origin = "idp-mock-saml-" + new RandomValueStringGenerator().generate();
        String metadata = BootstrapSamlIdentityProviderDataTests.XML_WITHOUT_ID.formatted("http://localhost:9999/metadata/" + origin);
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
        assertThat(created.getConfig()).isNotNull();
        createIdentityProvider(null, created, accessToken, status().isConflict());
        SamlIdentityProviderDefinition samlCreated = created.getConfig();
        assertThat(samlCreated.getEmailDomain()).isEqualTo(Arrays.asList("test.com", "test2.com"));
        assertThat(samlCreated.getExternalGroupsWhitelist()).isEqualTo(externalGroupsWhitelist);
        assertThat(samlCreated.getAttributeMappings()).isEqualTo(attributeMappings);
        assertThat(samlCreated.getZoneId()).isEqualTo(IdentityZone.getUaaZoneId());
        assertThat(samlCreated.getIdpEntityAlias()).isEqualTo(provider.getOriginKey());

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
    void delete_with_invalid_id_returns_404() throws Exception {
        String accessToken = setUpAccessToken();
        mockMvc.perform(
                delete("/identity-providers/invalid-id")
                        .header("Authorization", "Bearer" + accessToken)
        ).andExpect(status().isNotFound());
    }

    @Test
    void delete_response_not_containing_relying_party_secret() throws Exception {
        UaaClientDetails client = getUaaBaseClientDetails();
        ScimUser user = MockMvcUtils.createAdminForZone(mockMvc, adminToken, "idps.read,idps.write", IdentityZone.getUaaZoneId());
        String accessToken = MockMvcUtils.getUserOAuthAccessToken(mockMvc, client.getClientId(), client.getClientSecret(), user.getUserName(), "secr3T", "idps.read,idps.write");

        String originKey = RandomStringUtils.randomAlphabetic(6);
        OIDCIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();
        definition.setDiscoveryUrl(URI.create("https://accounts.google.com/.well-known/openid-configuration").toURL());
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
        assertThat(((AbstractExternalOAuthIdentityProviderDefinition) returnedIdentityProvider.getConfig())
                .getRelyingPartySecret()).isNull();
    }

    @Test
    void delete_response_not_containing_bind_password() throws Exception {
        UaaClientDetails client = getUaaBaseClientDetails();
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
                     InMemoryLdapServer.startLdap()) {
            providerDefinition.setBaseUrl(ldapServer.getUrl());
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
            assertThat(((LdapIdentityProviderDefinition) returnedIdentityProvider.
                    getConfig()).getBindPassword()).isNull();
        }
    }

    @Test
    void ensureWeRetrieveInactiveIDPsToo() throws Exception {
        testRetrieveIdps(false);
    }

    @Test
    void retrieveOnlyActiveIdps() throws Exception {
        testRetrieveIdps(true);
    }

    @Test
    void createIdentityProviderWithInsufficientScopes() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("testorigin", IdentityZone.getUaaZoneId());
        createIdentityProvider(null, identityProvider, lowPrivilegeToken, status().isForbidden());
        assertThat(eventListener.getEventCount()).isZero();
    }

    @Test
    void updateIdentityProviderWithInsufficientScopes() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("testorigin", IdentityZone.getUaaZoneId());
        updateIdentityProvider(null, identityProvider, lowPrivilegeToken, status().isForbidden());
        assertThat(eventListener.getEventCount()).isZero();
    }

    @Test
    void updateUaaIdentityProviderDoesUpdateOfPasswordPolicy() throws Exception {
        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaaZoneId());
        long expireMonths = System.nanoTime() % 100L;
        PasswordPolicy newConfig = new PasswordPolicy(6, 20, 1, 1, 1, 0, (int) expireMonths);
        identityProvider.setConfig(new UaaIdentityProviderDefinition(newConfig, null));
        String accessToken = setUpAccessToken();
        updateIdentityProvider(null, identityProvider, accessToken, status().isOk());
        IdentityProvider modifiedIdentityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaaZoneId());
        assertThat(((UaaIdentityProviderDefinition) modifiedIdentityProvider.getConfig()).getPasswordPolicy()).isEqualTo(newConfig);
    }

    @Test
    void updateUaaIdentityProviderDoesUpdateOfPasswordPolicyWithPasswordNewerThan() throws Exception {
        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaaZoneId());
        long expireMonths = System.nanoTime() % 100L;
        PasswordPolicy newConfig = new PasswordPolicy(6, 20, 1, 1, 1, 0, (int) expireMonths);
        newConfig.setPasswordNewerThan(new Date());
        identityProvider.setConfig(new UaaIdentityProviderDefinition(newConfig, null));
        String accessToken = setUpAccessToken();
        updateIdentityProvider(null, identityProvider, accessToken, status().isOk());
        IdentityProvider modifiedIdentityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaaZoneId());
        assertThat(((UaaIdentityProviderDefinition) modifiedIdentityProvider.getConfig()).getPasswordPolicy()).isEqualTo(newConfig);
    }

    @Test
    void malformedPasswordPolicyReturnsUnprocessableEntity() throws Exception {
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
    void createAndUpdateIdentityProviderInOtherZone() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("testorigin", IdentityZone.getUaaZoneId());
        IdentityZone zone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityToken);
        ScimUser user = MockMvcUtils.createAdminForZone(mockMvc, adminToken, "zones." + zone.getId() + ".idps.write", IdentityZone.getUaaZoneId());

        String userAccessToken = MockMvcUtils.getUserOAuthAccessTokenAuthCode(mockMvc, "identity", "identitysecret", user.getId(), user.getUserName(), "secr3T", "zones." + zone.getId() + ".idps.write");
        eventListener.clearEvents();
        IdentityProvider createdIDP = createIdentityProvider(zone.getId(), identityProvider, userAccessToken, status().isCreated());

        assertThat(createdIDP.getId()).isNotNull();
        assertThat(createdIDP.getName()).isEqualTo(identityProvider.getName());
        assertThat(createdIDP.getOriginKey()).isEqualTo(identityProvider.getOriginKey());
        assertThat(eventListener.getEventCount()).isOne();
        IdentityProviderModifiedEvent event = eventListener.getLatestEvent();
        assertThat(event.getAuditEvent().getType()).isEqualTo(AuditEventType.IdentityProviderCreatedEvent);
    }

    @Test
    void create_duplicate_saml_identity_provider_in_other_zone() throws Exception {
        String origin1 = "IDPEndpointsMockTests1-" + new RandomValueStringGenerator().generate();
        String origin2 = "IDPEndpointsMockTests2-" + new RandomValueStringGenerator().generate();

        IdentityZone zone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityToken);
        ScimUser user = MockMvcUtils.createAdminForZone(mockMvc, adminToken, "zones." + zone.getId() + ".idps.write", IdentityZone.getUaaZoneId());

        String userAccessToken = MockMvcUtils.getUserOAuthAccessTokenAuthCode(mockMvc, "identity", "identitysecret", user.getId(), user.getUserName(), "secr3T", "zones." + zone.getId() + ".idps.write");
        eventListener.clearEvents();

        IdentityProvider<SamlIdentityProviderDefinition> identityProvider = MultitenancyFixture.identityProvider(origin1, zone.getId());
        identityProvider.setType(OriginKeys.SAML);

        SamlIdentityProviderDefinition providerDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(BootstrapSamlIdentityProviderDataTests.XML_WITHOUT_ID.formatted("http://www.okta.com/" + identityProvider.getOriginKey()))
                .setIdpEntityAlias(identityProvider.getOriginKey())
                .setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
                .setLinkText("IDPEndpointsMockTests Saml Provider:" + identityProvider.getOriginKey())
                .setZoneId(zone.getId());
        identityProvider.setConfig(providerDefinition);

        IdentityProvider<SamlIdentityProviderDefinition> createdIDP = createIdentityProvider(zone.getId(), identityProvider, userAccessToken, status().isCreated());

        assertThat(createdIDP.getId()).isNotNull();
        assertThat(createdIDP.getName()).isEqualTo(identityProvider.getName());
        assertThat(createdIDP.getOriginKey()).isEqualTo(identityProvider.getOriginKey());
        assertThat(createdIDP.getConfig().getIdpEntityAlias()).isEqualTo(identityProvider.getConfig().getIdpEntityAlias());
        assertThat(createdIDP.getConfig().getZoneId()).isEqualTo(identityProvider.getConfig().getZoneId());

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
    void create_duplicate_saml_identity_provider_in_default_zone() throws Exception {
        String origin1 = "IDPEndpointsMockTests3-" + new RandomValueStringGenerator().generate();
        String origin2 = "IDPEndpointsMockTests4-" + new RandomValueStringGenerator().generate();
        String userAccessToken = setUpAccessToken();
        eventListener.clearEvents();

        IdentityProvider identityProvider = MultitenancyFixture.identityProvider(origin1, IdentityZone.getUaaZoneId());
        identityProvider.setType(OriginKeys.SAML);

        SamlIdentityProviderDefinition providerDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(BootstrapSamlIdentityProviderDataTests.XML_WITHOUT_ID.formatted("http://www.okta.com/" + identityProvider.getOriginKey()))
                .setIdpEntityAlias(identityProvider.getOriginKey())
                .setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
                .setLinkText("IDPEndpointsMockTests Saml Provider:" + identityProvider.getOriginKey())
                .setZoneId(IdentityZone.getUaaZoneId());
        identityProvider.setConfig(providerDefinition);

        IdentityProvider createdIDP = createIdentityProvider(null, identityProvider, userAccessToken, status().isCreated());

        assertThat(createdIDP.getId()).isNotNull();
        assertThat(createdIDP.getName()).isEqualTo(identityProvider.getName());
        assertThat(createdIDP.getOriginKey()).isEqualTo(identityProvider.getOriginKey());

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
    void readIdentityProviderInOtherZoneUsingZonesToken() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("testorigin", IdentityZone.getUaaZoneId());
        IdentityZone zone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityToken);

        ScimUser user = MockMvcUtils.createAdminForZone(mockMvc, adminToken, "zones." + zone.getId() + ".idps.write", IdentityZone.getUaaZoneId());
        String userAccessToken = MockMvcUtils.getUserOAuthAccessTokenAuthCode(mockMvc, "identity", "identitysecret", user.getId(), user.getUserName(), "secr3T", "zones." + zone.getId() + ".idps.write");
        eventListener.clearEvents();
        IdentityProvider createdIDP = createIdentityProvider(zone.getId(), identityProvider, userAccessToken, status().isCreated());

        assertThat(createdIDP.getId()).isNotNull();
        assertThat(createdIDP.getName()).isEqualTo(identityProvider.getName());
        assertThat(createdIDP.getOriginKey()).isEqualTo(identityProvider.getOriginKey());

        addScopeToIdentityClient("zones.*.idps.read");
        user = MockMvcUtils.createAdminForZone(mockMvc, adminToken, "zones." + zone.getId() + ".idps.read", IdentityZone.getUaaZoneId());
        userAccessToken = MockMvcUtils.getUserOAuthAccessTokenAuthCode(mockMvc, "identity", "identitysecret", user.getId(), user.getUserName(), "secr3T", "zones." + zone.getId() + ".idps.read");

        MockHttpServletRequestBuilder requestBuilder = get("/identity-providers/" + createdIDP.getId())
                .header("Authorization", "Bearer" + userAccessToken)
                .header(IdentityZoneSwitchingFilter.HEADER, zone.getId())
                .contentType(APPLICATION_JSON);

        MvcResult result = mockMvc.perform(requestBuilder).andExpect(status().isOk()).andReturn();
        IdentityProvider retrieved = JsonUtils.readValue(result.getResponse().getContentAsString(), IdentityProvider.class);
        assertThat(retrieved).isEqualTo(createdIDP);
    }

    @Test
    void listIdpsInZone() throws Exception {
        UaaClientDetails client = getUaaBaseClientDetails();

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
        List<IdentityProvider> identityProviderList = JsonUtils.readValue(result.getResponse().getContentAsString(), new TypeReference<>() {
        });
        assertThat(identityProviderList)
                .hasSize(numberOfIdps + 1)
                .contains(newIdp);
    }

    @Test
    void listIdpsInOtherZoneFromDefaultZone() throws Exception {
        IdentityZone identityZone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityToken);
        ScimUser userInDefaultZone = MockMvcUtils.createAdminForZone(mockMvc, adminToken, "zones." + identityZone.getId() + ".idps.read" + ", zones." + identityZone.getId() + ".idps.write", IdentityZone.getUaaZoneId());
        String zoneAdminToken = MockMvcUtils.getUserOAuthAccessTokenAuthCode(mockMvc, "identity", "identitysecret", userInDefaultZone.getId(), userInDefaultZone.getUserName(), "secr3T", "zones." + identityZone.getId() + ".idps.read " + "zones." + identityZone.getId() + ".idps.write");

        IdentityProvider otherZoneIdp = MockMvcUtils.createIdpUsingWebRequest(mockMvc, identityZone.getId(), zoneAdminToken, MultitenancyFixture.identityProvider(new RandomValueStringGenerator().generate(), IdentityZone.getUaaZoneId()), status().isCreated());

        MockHttpServletRequestBuilder requestBuilder = get("/identity-providers/")
                .header("Authorization", "Bearer" + zoneAdminToken)
                .contentType(APPLICATION_JSON);
        requestBuilder.header(IdentityZoneSwitchingFilter.HEADER, identityZone.getId());

        MvcResult result = mockMvc.perform(requestBuilder).andExpect(status().isOk()).andReturn();
        List<IdentityProvider> identityProviderList = JsonUtils.readValue(result.getResponse().getContentAsString(), new TypeReference<>() {
        });
        assertThat(identityProviderList).contains(otherZoneIdp)
                .hasSize(2);
    }

    @Test
    void retrieveIdpInZone() throws Exception {
        UaaClientDetails client = getUaaBaseClientDetails();

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
        assertThat(retrieved).isEqualTo(newIdp);
    }

    @Test
    void retrieveIdpInZoneWithInsufficientScopes() throws Exception {
        UaaClientDetails client = getUaaBaseClientDetails();

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
    void listIdpsWithInsufficientScopes() {
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
        assertThat(response).doesNotContain("relyingPartySecret");
        identityProvider = JsonUtils.readValue(response, new TypeReference<>() {
        });
        assertThat(identityProvider.getConfig().isClientAuthInBody()).isTrue();

        assertThat(((AbstractExternalOAuthIdentityProviderDefinition) webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class).retrieve(identityProvider.getId(), identityProvider.getIdentityZoneId()).getConfig())
                .isClientAuthInBody()).isTrue();

        identityProvider.getConfig().setClientAuthInBody(false);

        mvcResult = mockMvc.perform(put("/identity-providers/" + identityProvider.getId())
                .header("Authorization", "bearer " + adminToken)
                .content(JsonUtils.writeValueAsString(identityProvider))
                .contentType(APPLICATION_JSON)
        ).andExpect(status().isOk()).andReturn();
        response = mvcResult.getResponse().getContentAsString();
        assertThat(response).doesNotContain("relyingPartySecret");
        identityProvider = JsonUtils.readValue(response, new TypeReference<>() {
        });
        assertThat(identityProvider.getConfig().isClientAuthInBody()).isFalse();
        assertThat(((AbstractExternalOAuthIdentityProviderDefinition) webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class).retrieve(identityProvider.getId(), identityProvider.getIdentityZoneId()).getConfig())
                .isClientAuthInBody()).isFalse();

        identityProvider.getConfig().setTokenUrl(null);

        mockMvc.perform(put("/identity-providers/" + identityProvider.getId())
                .header("Authorization", "bearer " + adminToken)
                .content(JsonUtils.writeValueAsString(identityProvider))
                .contentType(APPLICATION_JSON)
        ).andExpect(status().isUnprocessableEntity());
    }

    @Test
    void updatePasswordPolicyWithPasswordNewerThan() throws Exception {
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
        assertThat(updatedStatus.getRequirePasswordChange()).isEqualTo(identityProviderStatus.getRequirePasswordChange());
    }

    private IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> getOAuthProviderConfig() throws MalformedURLException {
        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> identityProvider = new IdentityProvider<>();
        identityProvider.setName("my oidc provider");
        identityProvider.setIdentityZoneId(OriginKeys.UAA);
        OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition();
        config.addAttributeMapping(USER_NAME_ATTRIBUTE_NAME, "user_name");
        config.setAuthUrl(URI.create("http://oidc10.uaa.com/oauth/authorize").toURL());
        config.setTokenUrl(URI.create("http://oidc10.uaa.com/oauth/token").toURL());
        config.setTokenKeyUrl(URI.create("http://oidc10.uaa.com/token_key").toURL());
        config.setShowLinkText(true);
        config.setLinkText("My OIDC Provider");
        config.setSkipSslValidation(true);
        config.setRelyingPartyId("identity");
        config.setRelyingPartySecret("identitysecret");
        identityProvider.setConfig(config);
        identityProvider.setOriginKey("puppy");
        return identityProvider;
    }

    private UaaClientDetails getUaaBaseClientDetails() throws Exception {
        String clientId = RandomStringUtils.randomAlphabetic(6);
        UaaClientDetails client = new UaaClientDetails(clientId, null, "idps.read,idps.write", "password", null);
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
        UaaClientDetails client = new UaaClientDetails(clientId, null, "idps.write,idps.read", "password", null);
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
        List<IdentityProvider> identityProviderList = JsonUtils.readValue(result.getResponse().getContentAsString(), new TypeReference<>() {
        });
        assertThat(identityProviderList).hasSize(numberOfIdps)
                .contains(createdIDP);

        createdIDP.setActive(false);
        createdIDP = JsonUtils.readValue(updateIdentityProvider(null, createdIDP, accessToken, status().isOk()).getResponse().getContentAsString(), IdentityProvider.class);

        result = mockMvc.perform(requestBuilder).andExpect(status().isOk()).andReturn();
        identityProviderList = JsonUtils.readValue(result.getResponse().getContentAsString(), new TypeReference<>() {
        });
        if (!retrieveActive) {
            assertThat(identityProviderList).hasSize(numberOfIdps)
                    .contains(createdIDP);
        } else {
            assertThat(identityProviderList)
                    .hasSize(numberOfIdps - 1)
                    .doesNotContain(createdIDP);
        }
    }

    private IdentityProvider createAndUpdateIdentityProvider(String accessToken) throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("testorigin", IdentityZone.getUaaZoneId());
        // create
        // check response
        IdentityProvider createdIDP = createIdentityProvider(null, identityProvider, accessToken, status().isCreated());
        assertThat(createdIDP.getId()).isNotNull();
        assertThat(createdIDP.getName()).isEqualTo(identityProvider.getName());
        assertThat(createdIDP.getOriginKey()).isEqualTo(identityProvider.getOriginKey());

        // check audit
        assertThat(eventListener.getEventCount()).isOne();
        IdentityProviderModifiedEvent event = eventListener.getLatestEvent();
        assertThat(event.getAuditEvent().getType()).isEqualTo(AuditEventType.IdentityProviderCreatedEvent);

        // check db
        IdentityProvider persisted = identityProviderProvisioning.retrieve(createdIDP.getId(), createdIDP.getIdentityZoneId());
        assertThat(persisted.getId()).isNotNull();
        assertThat(persisted.getName()).isEqualTo(identityProvider.getName());
        assertThat(persisted.getOriginKey()).isEqualTo(identityProvider.getOriginKey());

        // update
        createdIDP.setConfig(new UaaIdentityProviderDefinition(null, null));
        updateIdentityProvider(null, createdIDP, accessToken, status().isOk());

        // check db
        persisted = identityProviderProvisioning.retrieve(createdIDP.getId(), createdIDP.getIdentityZoneId());
        assertThat(persisted.getId()).isEqualTo(createdIDP.getId());
        assertThat(persisted.getName()).isEqualTo(createdIDP.getName());
        assertThat(persisted.getOriginKey()).isEqualTo(createdIDP.getOriginKey());
        assertThat(persisted.getConfig()).isEqualTo(createdIDP.getConfig());

        // check audit
        assertThat(eventListener.getEventCount()).isEqualTo(2);
        event = eventListener.getLatestEvent();
        assertThat(event.getAuditEvent().getType()).isEqualTo(AuditEventType.IdentityProviderModifiedEvent);

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
            assertThat(template.update("UPDATE oauth_client_details SET scope=? WHERE identity_zone_id='uaa' AND client_id='identity'", scopes)).isOne();
        }
    }

    private String setUpAccessToken() throws Exception {
        String clientId = RandomStringUtils.randomAlphabetic(6);
        UaaClientDetails client = new UaaClientDetails(clientId, null, "idps.read,idps.write", "password", null);
        client.setClientSecret("test-client-secret");
        MockMvcUtils.createClient(mockMvc, adminToken, client);

        ScimUser user = MockMvcUtils.createAdminForZone(mockMvc, adminToken, "idps.write,idps.read", IdentityZone.getUaaZoneId());
        return MockMvcUtils.getUserOAuthAccessToken(mockMvc, client.getClientId(), client.getClientSecret(), user.getUserName(), "secr3T", "idps.read idps.write");
    }
}
