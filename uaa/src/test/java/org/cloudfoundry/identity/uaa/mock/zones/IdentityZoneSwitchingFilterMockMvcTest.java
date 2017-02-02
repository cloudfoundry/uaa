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
package org.cloudfoundry.identity.uaa.mock.zones;

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.ResultMatcher;

import java.util.Arrays;
import java.util.UUID;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.utils;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter.HEADER;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER;
import static org.junit.Assert.assertEquals;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class IdentityZoneSwitchingFilterMockMvcTest extends InjectedMockContextTest {

    private String identityToken;
    private String adminToken;
    private RandomValueStringGenerator generator;

    @Before
    public void setUp() throws Exception {
        identityToken = testClient.getClientCredentialsOAuthAccessToken(
                "identity",
                "identitysecret",
                "zones.write,scim.zones");

        adminToken = testClient.getClientCredentialsOAuthAccessToken(
            "admin",
            "adminsecret",
            "");

        generator = new RandomValueStringGenerator();
    }

    @Test
    public void testSwitchingZones() throws Exception {

        IdentityZone identityZone = createZone(identityToken);
        String zoneId = identityZone.getId();
        String zoneAdminToken = utils().getZoneAdminToken(getMockMvc(),adminToken, zoneId);
        // Using Identity Client, authenticate in originating Zone
        // - Create Client using X-Identity-Zone-Id header in new Zone
        ClientDetails client = createClientInOtherZone(zoneAdminToken, status().isCreated(), HEADER, zoneId);

        // Authenticate with new Client in new Zone
        getMockMvc().perform(post("/oauth/token")
            .param("grant_type","client_credentials")
            .header("Authorization", "Basic "
                + new String(Base64.encodeBase64((client.getClientId() + ":" + client.getClientSecret()).getBytes())))
            .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk());
    }

    @Test
    public void testSwitchingZoneWithSubdomain() throws Exception {
        IdentityZone identityZone = createZone(identityToken);
        String zoneAdminToken = utils().getZoneAdminToken(getMockMvc(),adminToken, identityZone.getId());
        ClientDetails client = createClientInOtherZone(zoneAdminToken, status().isCreated(), SUBDOMAIN_HEADER, identityZone.getSubdomain());

        getMockMvc().perform(
            post("/oauth/token")
                .param("grant_type","client_credentials")
                .header("Authorization", "Basic "
                        + new String(Base64.encodeBase64((client.getClientId() + ":" + client.getClientSecret()).getBytes())))
                .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk());

    }

    @Test
    public void testNoSwitching() throws Exception{

        final String clientId = UUID.randomUUID().toString();
        BaseClientDetails client = new BaseClientDetails(clientId, null, null, "client_credentials", null);
        client.setClientSecret("secret");

        getMockMvc().perform(post("/oauth/clients")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isCreated());

        getMockMvc().perform(
            post("/oauth/token")
                .param("grant_type", "client_credentials")
                .header("Authorization", "Basic "
                    + new String(Base64.encodeBase64((client.getClientId() + ":" + client.getClientSecret()).getBytes()))))
            .andExpect(status().isOk());
    }

    @Test
    public void testSwitchingToInvalidSubDomain() throws Exception{
        IdentityZone identityZone = createZone(identityToken);
        String zoneAdminToken = utils().getZoneAdminToken(getMockMvc(),adminToken, identityZone.getId());

        createClientInOtherZone(zoneAdminToken, status().isNotFound(), SUBDOMAIN_HEADER, "InvalidSubDomain");
    }

    @Test
    public void testSwitchingToNonExistentZone() throws Exception {
        IdentityZone identityZone = createZone(identityToken);
        String zoneAdminToken = utils().getZoneAdminToken(getMockMvc(),adminToken, identityZone.getId());

        createClientInOtherZone(zoneAdminToken, status().isNotFound(), HEADER, "i-do-not-exist");
    }

    @Test
    public void testSwitchingZonesWithoutAuthority() throws Exception {
        String identityTokenWithoutZonesAdmin = testClient.getClientCredentialsOAuthAccessToken("identity","identitysecret","zones.write,scim.zones");
        final String zoneId = createZone(identityTokenWithoutZonesAdmin).getId();
        createClientInOtherZone(identityTokenWithoutZonesAdmin, status().isForbidden(), HEADER, zoneId);
    }

    @Test
    public void testSwitchingZonesWithAUser() throws Exception {
        final String zoneId = createZone(identityToken).getId();
        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin","adminsecret","scim.write");
        // Create a User
        String username = generator.generate() + "@example.com";
        ScimUser user = getScimUser(username);
        ScimUser createdUser = utils().createUser(getMockMvc(), adminToken, user);
        ScimGroup group = new ScimGroup(null, "zones." + zoneId + ".admin", zoneId);
        group.setMembers(Arrays.asList(new ScimGroupMember(createdUser.getId())));
        utils().createGroup(getMockMvc(), adminToken, group);
        String userToken = utils().getUserOAuthAccessTokenAuthCode(getMockMvc(),"identity", "identitysecret", createdUser.getId(),createdUser.getUserName(), "secret", null);
        createClientInOtherZone(userToken, status().isCreated(), HEADER, zoneId);
    }

    protected ScimUser getScimUser(String username) {
        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.addEmail(username);
        user.setPassword("secr3T");
        user.setVerified(true);
        user.setZoneId(IdentityZone.getUaa().getId());
        return user;
    }

    @Test
    public void test_scim_read_in_another_zone() throws Exception {
        final String zoneId = createZone(identityToken).getId();
        ScimUser user = createScimUserUsingZonesScimWrite(zoneId);
        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin","adminsecret","scim.write");
        String scimReadZoneToken = utils().getZoneAdminToken(getMockMvc(), adminToken, zoneId, "zones."+zoneId+".scim.read");
        ScimUser readUser = utils().readUserInZone(getMockMvc(), scimReadZoneToken, user.getId(), "", zoneId);
        assertEquals(user.getId(), readUser.getId());
    }

    @Test
    public void test_scim_create_in_another_zone() throws Exception {
        final String zoneId = createZone(identityToken).getId();
        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin","adminsecret","scim.write");
        String scimCreateZoneToken = utils().getZoneAdminToken(getMockMvc(), adminToken, zoneId, "zones."+zoneId+".scim.create");
        createUserInAnotherZone(scimCreateZoneToken, zoneId);
    }

    @Test
    public void test_scim_write_in_another_zone() throws Exception {
        final String zoneId = createZone(identityToken).getId();
        createScimUserUsingZonesScimWrite(zoneId);
    }
    public ScimUser createScimUserUsingZonesScimWrite(String zoneId) throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin","adminsecret","scim.write");
        String scimWriteZoneToken = utils().getZoneAdminToken(getMockMvc(), adminToken, zoneId, "zones."+zoneId+".scim.write");
        return createUserInAnotherZone(scimWriteZoneToken, zoneId);
    }

    private IdentityZone createZone(String accessToken) throws Exception {
        return utils().createZoneUsingWebRequest(getMockMvc(), accessToken);
    }

    private ScimUser createUserInAnotherZone(String accessToken, String zoneId) throws Exception {
        String username = generator.generate() + "@example.com";
        ScimUser user = getScimUser(username);
        ScimUser createdUser = utils().createUserInZone(getMockMvc(), accessToken, user, "", zoneId);
        return createdUser;
    }

    private ClientDetails createClientInOtherZone(String accessToken, ResultMatcher statusMatcher, String headerKey, String headerValue) throws Exception {
        String clientId = generator.generate();
        BaseClientDetails client = new BaseClientDetails(clientId, null, null, "client_credentials", null);
        client.setClientSecret("secret");
        getMockMvc().perform(post("/oauth/clients")
            .header(headerKey, headerValue)
            .header("Authorization", "Bearer " + accessToken)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(client)))
            .andExpect(statusMatcher);
        return client;
    }

}
