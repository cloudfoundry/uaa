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
package org.cloudfoundry.identity.uaa.mock.zones;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.RandomStringUtils;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.ResultMatcher;

import java.util.Arrays;
import java.util.UUID;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class IdentityZoneSwitchingFilterMockMvcTest extends InjectedMockContextTest {

    private TestClient testClient;
    private String identityToken;
    private String adminToken;

    @Before
    public void setUp() throws Exception {
        testClient = new TestClient(getMockMvc());
        identityToken = testClient.getClientCredentialsOAuthAccessToken(
                "identity",
                "identitysecret",
                "zones.write,scim.zones");

        adminToken = testClient.getClientCredentialsOAuthAccessToken(
            "admin",
            "adminsecret",
            "");
    }

    @Test
    public void testSwitchingZones() throws Exception {

        final String zoneId = createZone(identityToken);
        String zoneAdminToken = MockMvcUtils.utils().getZoneAdminToken(getMockMvc(),adminToken, zoneId);
        // Using Identity Client, authenticate in originating Zone
        // - Create Client using X-Identity-Zone-Id header in new Zone
        final String clientId = UUID.randomUUID().toString();
        BaseClientDetails client = new BaseClientDetails(clientId, null, null, "client_credentials", null);
        client.setClientSecret("secret");
        getMockMvc().perform(post("/oauth/clients")
            .header(IdentityZoneSwitchingFilter.HEADER, zoneId)
            .header("Authorization", "Bearer " + zoneAdminToken)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(client)))
            .andExpect(status().isCreated());

        // Authenticate with new Client in new Zone
        getMockMvc().perform(get("/oauth/token?grant_type=client_credentials")
            .header("Authorization", "Basic "
                + new String(Base64.encodeBase64((client.getClientId() + ":" + client.getClientSecret()).getBytes())))
            .with(new SetServerNameRequestPostProcessor(zoneId + ".localhost")))
                .andExpect(status().isOk());
    }

    @Test
    public void testSwitchingToNonExistentZone() throws Exception {
        createClientInOtherZone(identityToken, "i-do-not-exist", status().isForbidden());
    }

    @Test
    public void testSwitchingZonesWithoutAuthority() throws Exception {
        String identityTokenWithoutZonesAdmin = testClient.getClientCredentialsOAuthAccessToken("identity","identitysecret","zones.write,scim.zones");
        final String zoneId = createZone(identityTokenWithoutZonesAdmin);
        createClientInOtherZone(identityTokenWithoutZonesAdmin, zoneId, status().isForbidden());
    }

    @Test
    public void testSwitchingZonesWithAUser() throws Exception {
        final String zoneId = createZone(identityToken);
        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin","adminsecret","scim.write");
        // Create a User
        String username = RandomStringUtils.randomAlphabetic(8) + "@example.com";
        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.addEmail(username);
        user.setPassword("secret");
        user.setVerified(true);
        user.setZoneId(IdentityZone.getUaa().getId());
        ScimUser createdUser = MockMvcUtils.utils().createUser(getMockMvc(), adminToken, user);
        // Create the zones.<zone_id>.admin Group
        // Add User to the zones.<zone_id>.admin Group
        ScimGroup group = new ScimGroup("zones." + zoneId + ".admin");
        group.setMembers(Arrays.asList(new ScimGroupMember(createdUser.getId())));
        group = MockMvcUtils.utils().createGroup(getMockMvc(), adminToken, group);
        // Add User to the clients.create Group
        //String userToken = testClient.getUserOAuthAccessToken("identity", "identitysecret", createdUser.getUserName(), "secret", "zones." + zoneId + ".admin");
        String userToken = MockMvcUtils.utils().getUserOAuthAccessTokenAuthCode(getMockMvc(),"identity", "identitysecret", createdUser.getId(),createdUser.getUserName(), "secret", "zones." + zoneId + ".admin");
        createClientInOtherZone(userToken, zoneId, status().isCreated());
    }

    private String createZone(String accessToken) throws Exception {
        return MockMvcUtils.utils().createZoneUsingWebRequest(getMockMvc(), accessToken).getId();
    }

    private void createClientInOtherZone(String accessToken, String zoneId, ResultMatcher statusMatcher) throws Exception {
        final String clientId = UUID.randomUUID().toString();
        BaseClientDetails client = new BaseClientDetails(clientId, null, null, "client_credentials", null);
        client.setClientSecret("secret");
        getMockMvc().perform(post("/oauth/clients")
            .header(IdentityZoneSwitchingFilter.HEADER, zoneId)
            .header("Authorization", "Bearer " + accessToken)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(client)))
            .andExpect(statusMatcher);
    }
}
