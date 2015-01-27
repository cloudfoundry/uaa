/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.mock.util;


import java.util.UUID;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneCreationRequest;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import scala.actors.threadpool.Arrays;

public class MockMvcUtils {

    public static MockMvcUtils utils() {
        return new MockMvcUtils();
    }

    public IdentityZone createZoneUsingWebRequest(MockMvc mockMvc, String accessToken) throws Exception {
        final String zoneId = UUID.randomUUID().toString();
        IdentityZone identityZone = MultitenancyFixture.identityZone(zoneId, zoneId);

        IdentityZoneCreationRequest creationRequest = new IdentityZoneCreationRequest();
        creationRequest.setIdentityZone(identityZone);

        MvcResult result = mockMvc.perform(post("/identity-zones")
            .header("Authorization", "Bearer " + accessToken)
            .contentType(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsString(creationRequest)))
            .andExpect(status().isCreated()).andReturn();
        return new ObjectMapper().readValue(result.getResponse().getContentAsByteArray(), IdentityZone.class);
    }

    public ScimUser createUser(MockMvc mockMvc, String accessToken, ScimUser user) throws Exception {
        MvcResult userResult = mockMvc.perform(post("/Users")
            .header("Authorization", "Bearer " + accessToken)
            .contentType(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsBytes(user)))
            .andExpect(status().isCreated()).andReturn();
        return new ObjectMapper().readValue(userResult.getResponse().getContentAsString(), ScimUser.class);
    }

    public ScimGroup createGroup(MockMvc mockMvc, String accessToken, ScimGroup group) throws Exception {
        return new ObjectMapper().readValue(
            mockMvc.perform(post("/Groups")
            .header("Authorization", "Bearer " + accessToken)
            .contentType(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsBytes(group)))
            .andExpect(status().isCreated())
            .andReturn().getResponse().getContentAsByteArray(),
            ScimGroup.class);
    }

    public BaseClientDetails createClient(MockMvc mockMvc, String accessToken, BaseClientDetails clientDetails) throws Exception {
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
            .header("Authorization", "Bearer " + accessToken)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsString(clientDetails));
        return new ObjectMapper().readValue(
            mockMvc.perform(createClientPost)
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsByteArray(),BaseClientDetails.class);
    }

    public String getZoneAdminToken(MockMvc mockMvc, String adminToken, String zoneId) throws Exception {
        ScimUser user = new ScimUser();
        user.setUserName(new RandomValueStringGenerator().generate());
        user.setPrimaryEmail(user.getUserName()+"@test.org");
        user.setPassword("secret");
        user = MockMvcUtils.utils().createUser(mockMvc, adminToken, user);
        ScimGroup group = new ScimGroup("zones."+zoneId+".admin");
        group.setMembers(Arrays.asList(new ScimGroupMember[]{new ScimGroupMember(user.getId())}));
        MockMvcUtils.utils().createGroup(mockMvc, adminToken, group);
        return getUserOAuthAccessToken(mockMvc, "identity", "identitysecret", user.getUserName(), "secret", group.getDisplayName());
    }

    public String getUserOAuthAccessToken(MockMvc mockMvc, String clientId, String clientSecret, String username, String password, String scope)
        throws Exception {
        String basicDigestHeaderValue = "Basic "
            + new String(Base64.encodeBase64((clientId + ":" + clientSecret).getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
            .header("Authorization", basicDigestHeaderValue)
            .param("grant_type", "password")
            .param("client_id", clientId)
            .param("username", username)
            .param("password", password)
            .param("scope", scope);
        MvcResult result = mockMvc.perform(oauthTokenPost).andExpect(status().isOk()).andReturn();
        TestClient.OAuthToken oauthToken = new ObjectMapper().readValue(result.getResponse().getContentAsByteArray(), TestClient.OAuthToken.class);
        return oauthToken.accessToken;
    }

}
