/*
 * *****************************************************************************
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
package org.cloudfoundry.identity.uaa.integration;

import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.apache.hc.client5.http.impl.cookie.BasicClientCookie;
import org.cloudfoundry.identity.uaa.ServerRunningExtension;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.client.http.OAuth2ErrorHandler;
import org.cloudfoundry.identity.uaa.oauth.client.test.OAuth2ContextConfiguration;
import org.cloudfoundry.identity.uaa.oauth.client.test.OAuth2ContextExtension;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestAccountExtension;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.doesSupportZoneDNS;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.getHeaders;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.USER_OAUTH_APPROVAL;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME;

@OAuth2ContextConfiguration(OAuth2ContextConfiguration.ClientCredentials.class)
class ScimGroupEndpointsIntegrationTests {

    private ScimGroupMember dale;
    private ScimGroupMember joel;
    private ScimGroupMember vidya;

    private final String deleteMe = "deleteme_" + new RandomValueStringGenerator().generate().toLowerCase();

    private final String cfDev = "cf_dev_" + new RandomValueStringGenerator().generate().toLowerCase();

    private final String cfMgr = "cf_mgr_" + new RandomValueStringGenerator().generate().toLowerCase();

    private final String cfid = "cfid_" + new RandomValueStringGenerator().generate().toLowerCase();

    private final List<String> allowedGroups = List.of(deleteMe, cfDev, cfMgr, cfid);

    private final String groupEndpoint = "/Groups";

    private final String userEndpoint = "/Users";

    private List<String> groupIds = new ArrayList<>();

    private static final List<String> defaultGroups = Arrays.asList("openid", "scim.me", "cloud_controller.read",
            "cloud_controller.write", "password.write", "scim.userids", "uaa.user", "approvals.me",
            "oauth.approvals", "cloud_controller_service_permissions.read", "profile", "roles", "user_attributes", "uaa.offline_token");

    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    private static final UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @RegisterExtension
    private static final TestAccountExtension testAccountExtension = TestAccountExtension.standard(serverRunning, testAccounts);

    @RegisterExtension
    private static final OAuth2ContextExtension context = OAuth2ContextExtension.withTestAccounts(serverRunning, testAccountExtension);

    private RestTemplate client;
    private List<ScimGroup> scimGroups;

    @BeforeEach
    void createRestTemplate() {
        client = (RestTemplate) serverRunning.getRestTemplate();
        client.setErrorHandler(new OAuth2ErrorHandler(context.getResource()) {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) {
                // pass through
            }
        });

        joel = new ScimGroupMember(createUser("joel_" + new RandomValueStringGenerator().generate().toLowerCase(), "Passwo3d").getId());
        dale = new ScimGroupMember(createUser("dale_" + new RandomValueStringGenerator().generate().toLowerCase(), "Passwo3d").getId());
        vidya = new ScimGroupMember(createUser("vidya_" + new RandomValueStringGenerator().generate().toLowerCase(), "Passwo3d").getId());
    }

    @AfterEach
    void tearDown() {
        deleteResource(userEndpoint, dale.getMemberId());
        deleteResource(userEndpoint, joel.getMemberId());
        deleteResource(userEndpoint, vidya.getMemberId());
        for (String id : groupIds) {
            deleteResource(groupEndpoint, id);
        }
    }

    @SuppressWarnings("rawtypes")
    private ResponseEntity<Map> deleteResource(String url, String id) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("If-Match", "*");
        return client.exchange(serverRunning.getUrl(url + "/{id}"), HttpMethod.DELETE, new HttpEntity<Void>(headers),
                Map.class, id);
    }

    private ScimUser createUser(String username, String password) {
        String adminClientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "admin", "adminsecret");
        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.setName(new ScimUser.Name(username, username));
        user.addEmail(username);
        user.setVerified(true);
        user.setPassword(password);
        return IntegrationTestUtils.createUser(adminClientCredentialsToken, serverRunning.getUrl("/"), user, null);
    }

    private ScimGroup createGroup(String name, ScimGroupMember... members) {
        ScimGroup g = new ScimGroup(null, name, IdentityZoneHolder.get().getId());
        List<ScimGroupMember> m = members != null ? Arrays.asList(members) : Collections.emptyList();
        g.setMembers(m);
        ScimGroup g1 = client.postForEntity(serverRunning.getUrl(groupEndpoint), g, ScimGroup.class).getBody();
        assertThat(g1.getDisplayName()).isEqualTo(name);
        assertThat(g1.getMembers()).hasSameSizeAs(m);
        groupIds.add(g1.getId());
        return g1;
    }

    private ScimGroup updateGroup(String id, String name, ScimGroupMember... members) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("If-Match", "*");
        ScimGroup g = new ScimGroup(null, name, IdentityZoneHolder.get().getId());
        List<ScimGroupMember> m = members != null ? Arrays.asList(members) : Collections.emptyList();
        g.setMembers(m);
        client.exchange(serverRunning.getUrl(groupEndpoint + "/{id}"), HttpMethod.PUT,
                new HttpEntity<>(g, headers), Map.class, id);
        ScimGroup g1 = client.exchange(serverRunning.getUrl(groupEndpoint + "/{id}"), HttpMethod.PUT,
                new HttpEntity<>(g, headers), ScimGroup.class, id).getBody();
        assertThat(g1.getDisplayName()).isEqualTo(name);
        assertThat(g1.getMembers()).hasSameSizeAs(m);
        return g1;
    }

    private void validateUserGroups(String id, String... groups) {
        List<String> groupNames = groups != null ? Arrays.asList(groups) : Collections.emptyList();
        assertThat(getUser(id).getGroups()).hasSize(groupNames.size() + defaultGroups.size());
        for (ScimUser.Group g : getUser(id).getGroups()) {
            assertThat(defaultGroups.contains(g.getDisplay()) || groupNames.contains(g.getDisplay())).isTrue();
        }
    }

    private ScimUser getUser(String id) {
        return client.getForEntity(serverRunning.getUrl(userEndpoint + "/{id}"), ScimUser.class, id).getBody();
    }

    @Test
    void getGroupsWithoutAttributesReturnsAllData() {
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = client.getForEntity(serverRunning.getUrl(groupEndpoint), Map.class);

        @SuppressWarnings("rawtypes")
        Map results = response.getBody();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat((Integer) results.get("totalResults")).as("There should be more than zero users").isPositive();
        assertThat(((Collection<?>) results.get("resources"))).as("There should be some resources").isNotEmpty();
        @SuppressWarnings("rawtypes")
        Map firstGroup = (Map) ((List) results.get("resources")).getFirst();
        assertThat(firstGroup).containsKey("id")
                .containsKey("displayName")
                .containsKey("schemas")
                .containsKey("meta");
    }

    @Test
    void createGroupSucceeds() {
        ScimGroup g1 = createGroup(cfid);
        // Check we can GET the group
        ScimGroup g2 = client.getForObject(serverRunning.getUrl(groupEndpoint + "/{id}"), ScimGroup.class, g1.getId());
        assertThat(g2).isEqualTo(g1);
    }

    @Test
    void createAllowedGroupSucceeds() throws URISyntaxException {
        String testZoneId = "testzone1";
        assertThat(doesSupportZoneDNS()).as("Expected testzone1.localhost and testzone2.localhost to resolve to 127.0.0.1").isTrue();
        String adminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning.getBaseUrl(), "admin", "adminsecret");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.getUserConfig().setAllowedGroups(allowedGroups);
        String zoneUrl = serverRunning.getBaseUrl().replace("localhost", testZoneId + ".localhost");
        String inZoneAdminToken = IntegrationTestUtils.createClientAdminTokenInZone(serverRunning.getBaseUrl(), adminToken, testZoneId, config);
        ScimGroup g1 = new ScimGroup(null, cfid, testZoneId);
        // Check we can GET the group
        ScimGroup g2 = IntegrationTestUtils.createOrUpdateGroup(inZoneAdminToken, null, zoneUrl, g1);
        assertThat(g2.getDisplayName()).isEqualTo(g1.getDisplayName());
        assertThat(IntegrationTestUtils.getGroup(inZoneAdminToken, null, zoneUrl, g1.getDisplayName()).getDisplayName()).isEqualTo(g1.getDisplayName());
        IntegrationTestUtils.deleteZone(serverRunning.getBaseUrl(), testZoneId, adminToken);
    }

    @Test
    void createNotAllowedGroupFailsCorrectly() throws URISyntaxException {
        String testZoneId = "testzone1";
        assertThat(doesSupportZoneDNS()).as("Expected testzone1.localhost and testzone2.localhost to resolve to 127.0.0.1").isTrue();
        final String notAllowed = "not_allowed_" + new RandomValueStringGenerator().generate().toLowerCase();
        String adminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning.getBaseUrl(), "admin", "adminsecret");
        ScimGroup g1 = new ScimGroup(null, notAllowed, testZoneId);
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.getUserConfig().setAllowedGroups(allowedGroups);
        String zoneUrl = serverRunning.getBaseUrl().replace("localhost", testZoneId + ".localhost");
        String inZoneAdminToken = IntegrationTestUtils.createClientAdminTokenInZone(serverRunning.getBaseUrl(), adminToken, testZoneId, config);
        RestTemplate template = new RestTemplate();
        HttpEntity entity = new HttpEntity<>(JsonUtils.writeValueAsBytes(g1), IntegrationTestUtils.getAuthenticatedHeaders(inZoneAdminToken));
        try {
            template.exchange(zoneUrl + "/Groups", HttpMethod.POST, entity, HashMap.class);
            fail("must fail");
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode().is4xxClientError()).isTrue();
            assertThat(e.getRawStatusCode()).isEqualTo(400);
            assertThat(e.getMessage()).contains("The group with displayName: " + g1.getDisplayName() + " is not allowed in Identity Zone " + testZoneId);
        } finally {
            IntegrationTestUtils.deleteZone(serverRunning.getBaseUrl(), testZoneId, adminToken);
        }
    }

    @Test
    void relyOnDefaultGroupsShouldAllowedGroupSucceed() throws URISyntaxException {
        String testZoneId = "testzone1";
        assertThat(doesSupportZoneDNS()).as("Expected testzone1.localhost and testzone2.localhost to resolve to 127.0.0.1").isTrue();
        String adminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning.getBaseUrl(), "admin", "adminsecret");

        final String ccReadGroupName = "cloud_controller_service_permissions.read";

        /* allowed groups are empty, but 'cloud_controller_service_permissions.read' is part of the default groups
         * -> this group should therefore nevertheless be created during zone creation */
        final IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.getUserConfig().setAllowedGroups(List.of());
        config.getUserConfig().setDefaultGroups(defaultGroups);

        final String zoneUrl = serverRunning.getBaseUrl().replace("localhost", testZoneId + ".localhost");
        // this creates/updates the zone with the new config -> also creates/updates the default groups
        final String inZoneAdminToken = IntegrationTestUtils.createClientAdminTokenInZone(serverRunning.getBaseUrl(), adminToken, testZoneId, config);

        // Check we can GET the group
        final ScimGroup ccGroupFromGetCall = IntegrationTestUtils.getGroup(inZoneAdminToken, null, zoneUrl, ccReadGroupName);
        assertThat(ccGroupFromGetCall).isNotNull();
        assertThat(ccGroupFromGetCall.getDisplayName()).isEqualTo(ccReadGroupName);

        IntegrationTestUtils.deleteZone(serverRunning.getBaseUrl(), testZoneId, adminToken);
    }

    @Test
    void changeDefaultGroupsAllowedGroupsUsageShouldSucceed() throws URISyntaxException {
        String testZoneId = "testzone1";
        assertThat(doesSupportZoneDNS()).as("Expected testzone1.localhost and testzone2.localhost to resolve to 127.0.0.1").isTrue();
        String adminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning.getBaseUrl(), "admin", "adminsecret");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();

        // ensure zone does not exist
        if (IntegrationTestUtils.zoneExists(serverRunning.getBaseUrl(), testZoneId, adminToken)) {
            IntegrationTestUtils.deleteZone(serverRunning.getBaseUrl(), testZoneId, adminToken);
        }

        // add a new group to the allowed groups
        final String allowed = "allowed_" + new RandomValueStringGenerator().generate().toLowerCase();
        List<String> newDefaultGroups = new ArrayList<>(defaultGroups);
        newDefaultGroups.add(allowed);
        config.getUserConfig().setAllowedGroups(List.of());
        config.getUserConfig().setDefaultGroups(newDefaultGroups);
        String zoneUrl = serverRunning.getBaseUrl().replace("localhost", testZoneId + ".localhost");
        // this creates the zone as well as all default groups
        String inZoneAdminToken = IntegrationTestUtils.createClientAdminTokenInZone(serverRunning.getBaseUrl(), adminToken, testZoneId, config);

        // creating the newly allowed group should fail, as it already exists
        RestTemplate template = new RestTemplate();
        ScimGroup g1 = new ScimGroup(null, allowed, testZoneId);
        HttpEntity entity = new HttpEntity<>(JsonUtils.writeValueAsBytes(g1), IntegrationTestUtils.getAuthenticatedHeaders(inZoneAdminToken));
        try {
            assertThatThrownBy(() -> template.exchange(zoneUrl + "/Groups", HttpMethod.POST, entity, HashMap.class))
                    .isInstanceOf(HttpClientErrorException.Conflict.class)
                    .hasMessageContaining("A group with displayName: %s already exists.".formatted(allowed));
        } finally {
            IntegrationTestUtils.deleteZone(serverRunning.getBaseUrl(), testZoneId, adminToken);
        }
    }

    @Test
    void createGroupWithMembersSucceeds() {
        ScimGroup g1 = createGroup(cfid, joel, dale, vidya);
        // Check we can GET the group
        ScimGroup g2 = client.getForObject(serverRunning.getUrl(groupEndpoint + "/{id}"), ScimGroup.class, g1.getId());
        assertThat(g2).isEqualTo(g1);
        assertThat(g2.getMembers())
                .hasSize(3)
                .contains(joel, dale, vidya);

        // check that User.groups is updated
        validateUserGroups(joel.getMemberId(), cfid);
        validateUserGroups(dale.getMemberId(), cfid);
        validateUserGroups(vidya.getMemberId(), cfid);
    }

    @Test
    void createGroupWithInvalidMembersFailsCorrectly() {
        ScimGroup g = new ScimGroup(null, cfid, IdentityZoneHolder.get().getId());
        ScimGroupMember m2 = new ScimGroupMember("wrongid");
        g.setMembers(Arrays.asList(vidya, m2));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> r = client.postForEntity(serverRunning.getUrl(groupEndpoint), g, Map.class);
        @SuppressWarnings("unchecked")
        Map<String, String> g1 = r.getBody();
        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(g1).containsKey("error")
                .containsKey("message");
        assertThat(g1.get("message")).contains("Invalid group member");

        // check that the group was not created
        @SuppressWarnings("unchecked")
        Map<String, Object> g2 = client.getForObject(
                serverRunning.getUrl(groupEndpoint + "?filter=displayName eq \"{name}\""), Map.class, cfid);
        assertThat(g2).containsKey("totalResults");
        assertThat((Integer) g2.get("totalResults")).isEqualTo(Integer.valueOf(0));
    }

    @Test
    void createGroupWithMemberGroupSucceeds() {
        ScimGroup g1 = createGroup(cfid, vidya);
        ScimGroupMember m2 = new ScimGroupMember(g1.getId(), ScimGroupMember.Type.GROUP);
        ScimGroup g2 = createGroup(cfDev, m2);

        // Check we can GET the group
        ScimGroup g3 = client.getForObject(serverRunning.getUrl(groupEndpoint + "/{id}"), ScimGroup.class, g2.getId());
        assertThat(g3).isEqualTo(g2);
        assertThat(g3.getMembers()).hasSize(1)
                .contains(m2);

        // check that User.groups is updated
        validateUserGroups(vidya.getMemberId(), cfid, cfDev);
    }

    @Test
    void createExistingGroupFailsCorrectly() {
        ScimGroup g1 = createGroup(cfid);
        @SuppressWarnings("unchecked")
        Map<String, String> g2 = client.postForEntity(serverRunning.getUrl(groupEndpoint), g1, Map.class).getBody();
        assertThat(g2).containsKey("error")
                .containsEntry("error", "scim_resource_already_exists");
    }

    @Test
    void deleteGroupUpdatesUser() {
        ScimGroup g1 = createGroup(deleteMe, dale, vidya);
        validateUserGroups(dale.getMemberId(), deleteMe);
        validateUserGroups(vidya.getMemberId(), deleteMe);

        deleteResource(groupEndpoint, g1.getId());

        // check that the group does not exist anymore
        @SuppressWarnings("unchecked")
        Map<String, Object> g2 = client.getForObject(
                serverRunning.getUrl(groupEndpoint + "?filter=displayName eq \"{name}\""), Map.class, deleteMe);
        assertThat(g2).containsKey("totalResults")
                .containsEntry("totalResults", 0);

        // check that group membership is updated
        validateUserGroups(dale.getMemberId());
        validateUserGroups(vidya.getMemberId());
    }

    @Test
    void deleteNonExistentGroupFailsCorrectly() {
        @SuppressWarnings("unchecked")
        Map<String, Object> g = deleteResource(groupEndpoint, deleteMe).getBody();
        assertThat(g).containsKey("error")
                .containsEntry("error", "scim_resource_not_found");
    }

    @Test
    void deleteMemberGroupUpdatesGroup() {
        ScimGroup g1 = createGroup(cfid, vidya);
        ScimGroupMember m2 = new ScimGroupMember(g1.getId(), ScimGroupMember.Type.GROUP);
        ScimGroup g2 = createGroup(cfDev, dale, m2);
        assertThat(g2.getMembers()).contains(m2);
        validateUserGroups(vidya.getMemberId(), cfid, cfDev);

        deleteResource(groupEndpoint, g1.getId());

        // check that parent group is updated
        ScimGroup g3 = client.getForObject(serverRunning.getUrl(groupEndpoint + "/{id}"), ScimGroup.class, g2.getId());
        assertThat(g3.getMembers()).hasSize(1)
                .doesNotContain(m2);
    }

    @Test
    void deleteMemberUserUpdatesGroups() {
        ScimGroupMember toDelete = new ScimGroupMember(createUser(deleteMe, "Passwo3d").getId());
        ScimGroup g1 = createGroup(cfid, joel, dale, toDelete);
        ScimGroup g2 = createGroup(cfMgr, dale, toDelete);
        deleteResource(userEndpoint, toDelete.getMemberId());

        // check that membership has been updated
        ScimGroup g3 = client.getForObject(serverRunning.getUrl(groupEndpoint + "/{id}"), ScimGroup.class, g1.getId());
        assertThat(g3.getMembers()).hasSize(2)
                .doesNotContain(toDelete);

        g3 = client.getForObject(serverRunning.getUrl(groupEndpoint + "/{id}"), ScimGroup.class, g2.getId());
        assertThat(g3.getMembers()).hasSize(1)
                .doesNotContain(toDelete);
    }

    @Test
    void updateGroupUpdatesMemberUsers() {
        ScimGroup g1 = createGroup(cfid, joel, vidya);
        ScimGroup g2 = createGroup(cfMgr, dale);
        ScimGroupMember m1 = new ScimGroupMember(g1.getId(), ScimGroupMember.Type.GROUP);
        ScimGroupMember m2 = new ScimGroupMember(g2.getId(), ScimGroupMember.Type.GROUP);
        ScimGroup g3 = createGroup(cfDev, m1, m2);

        validateUserGroups(joel.getMemberId(), cfid, cfDev);
        validateUserGroups(vidya.getMemberId(), cfid, cfDev);
        validateUserGroups(dale.getMemberId(), cfMgr, cfDev);

        ScimGroup g4 = updateGroup(g3.getId(), "new_name", m1);

        // check that we did not create a new group, but only updated the
        // existing one
        assertThat(g4).isEqualTo(g3);
        // check that member users were updated
        validateUserGroups(dale.getMemberId(), cfMgr);
        validateUserGroups(joel.getMemberId(), cfid, "new_name");
        validateUserGroups(vidya.getMemberId(), cfid, "new_name");
    }

    @Test
    void accessTokenReflectsGroupMembership() throws Exception {

        createTestClient(deleteMe, "secret", cfid);
        ScimUser user = createUser(deleteMe, "Passwo3d");
        createGroup(cfid, new ScimGroupMember(user.getId()));
        OAuth2AccessToken token = getAccessToken(deleteMe, "secret", deleteMe, "Passwo3d");
        assertThat(token.getScope()).as("Wrong token: " + token).contains(cfid);

        deleteTestClient(deleteMe);
        deleteResource(userEndpoint, user.getId());

    }

    @Test
    void accessTokenReflectsGroupMembershipForPasswordGrant() {

        createTestClient(deleteMe, "secret", cfid);
        ScimUser user = createUser(deleteMe, "Passwo3d");
        createGroup(cfid, new ScimGroupMember(user.getId()));
        OAuth2AccessToken token = getAccessTokenWithPassword(deleteMe, "secret", deleteMe, "Passwo3d");
        assertThat(token.getScope()).as("Wrong token: " + token).contains(cfid);

        deleteTestClient(deleteMe);
        deleteResource(userEndpoint, user.getId());
    }

    @BeforeEach
    void initScimGroups() {
        scimGroups = new ArrayList<>();
    }

    @AfterEach
    void teardownScimGroups() {
        for (ScimGroup scimGroup : scimGroups) {
            deleteResource(groupEndpoint, scimGroup.getId());
        }
    }

    @Test
    void extremeGroupPagination() {
        for (int i = 0; i < 502; i++) {
            ScimUser user = createUser("deleteme_" + new RandomValueStringGenerator().generate().toLowerCase(), "Passwo3d");
            scimGroups.add(createGroup("cfid_" + new RandomValueStringGenerator().generate().toLowerCase(), new ScimGroupMember(user.getId())));
        }

        ResponseEntity<Map> response = client.getForEntity(serverRunning.getUrl(groupEndpoint + "?count=502"), Map.class);

        Map results = response.getBody();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat((Integer) results.get("totalResults")).isGreaterThan(500);
        assertThat((List<?>) results.get("resources")).hasSize(500);
        assertThat(results).containsEntry("itemsPerPage", 500)
                .containsEntry("startIndex", 1);
    }

    private void createTestClient(String name, String secret, String scope) {
        OAuth2AccessToken token = getClientCredentialsAccessToken("clients.read,clients.write,clients.admin");
        HttpHeaders headers = getAuthenticatedHeaders(token);
        UaaClientDetails client = new UaaClientDetails(name, "", scope, "authorization_code,password",
                "scim.read,scim.write", "http://redirect.uri");
        client.setClientSecret(secret);
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
                HttpMethod.POST, new HttpEntity<>(client, headers), Void.class);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    private void deleteTestClient(String clientId) {
        OAuth2AccessToken token = getClientCredentialsAccessToken("clients.read,clients.write");
        HttpHeaders headers = getAuthenticatedHeaders(token);
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients/{client}"), HttpMethod.DELETE,
                new HttpEntity<Void>(headers),
                Void.class, clientId);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    private OAuth2AccessToken getClientCredentialsAccessToken(String scope) {

        String clientId = testAccounts.getAdminClientId();
        String clientSecret = testAccounts.getAdminClientSecret();

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "client_credentials");
        formData.add("client_id", clientId);
        formData.add("scope", scope);
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.set("Authorization",
                "Basic " + new String(Base64.encode("%s:%s".formatted(clientId, clientSecret).getBytes())));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap("/oauth/token", formData, headers);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        @SuppressWarnings("unchecked")
        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(response.getBody());
        return accessToken;
    }

    private HttpHeaders getAuthenticatedHeaders(OAuth2AccessToken token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer " + token.getValue());
        return headers;
    }

    private OAuth2AccessToken getAccessTokenWithPassword(String clientId, String clientSecret, String username,
                                                         String password) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("client_id", clientId);
        formData.add("grant_type", "password");
        formData.add("username", username);
        formData.add("password", password);
        HttpHeaders tokenHeaders = new HttpHeaders();
        tokenHeaders.set("Authorization", testAccounts.getAuthorizationHeader(clientId, clientSecret));
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> tokenResponse = serverRunning.postForMap("/oauth/token", formData, tokenHeaders);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        @SuppressWarnings("unchecked")
        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(tokenResponse.getBody());
        return accessToken;
    }

    private OAuth2AccessToken getAccessToken(String clientId, String clientSecret, String username, String password) throws URISyntaxException {
        BasicCookieStore cookies = new BasicCookieStore();

        URI uri = serverRunning.buildUri("/oauth/authorize").queryParam("response_type", "code")
                .queryParam("state", "mystateid").queryParam("client_id", clientId)
                .queryParam("redirect_uri", "http://redirect.uri").build();
        ResponseEntity<Void> result = serverRunning.createRestTemplate().exchange(
                uri.toString(), HttpMethod.GET, new HttpEntity<>(null, getHeaders(cookies)),
                Void.class);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        String location = result.getHeaders().getLocation().toString();
        IntegrationTestUtils.extractCookies(result, cookies);

        ResponseEntity<String> response = serverRunning.getForString(location, getHeaders(cookies));
        // should be directed to the login screen...
        assertThat(response.getBody()).contains("/login.do")
                .contains("username")
                .contains("password");

        if (response.getHeaders().containsKey("Set-Cookie")) {
            String cookie = response.getHeaders().getFirst("Set-Cookie");
            int nameLength = cookie.indexOf('=');
            cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength + 1)));
        }

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("username", username);
        formData.add("password", password);
        formData.add(DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(response.getBody()));

        // Should be redirected to the original URL, but now authenticated
        result = serverRunning.postForResponse("/login.do", getHeaders(cookies), formData);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.FOUND);

        cookies.clear();
        IntegrationTestUtils.extractCookies(result, cookies);

        response = serverRunning.createRestTemplate().exchange(
                new URI(result.getHeaders().getLocation().toString()),
                HttpMethod.GET,
                new HttpEntity<>(null, getHeaders(cookies)),
                String.class);
        IntegrationTestUtils.extractCookies(response, cookies);

        if (response.getStatusCode() == HttpStatus.OK) {
            // The grant access page should be returned
            assertThat(response.getBody()).contains("<h1>Application Authorization</h1>");

            formData.clear();
            formData.add(DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(response.getBody()));
            formData.add(USER_OAUTH_APPROVAL, "true");
            formData.add("scope.0", "scope." + cfid);
            result = serverRunning.postForResponse("/oauth/authorize", getHeaders(cookies), formData);
            assertThat(result.getStatusCode()).isEqualTo(HttpStatus.FOUND);
            location = result.getHeaders().getLocation().toString();
        } else {
            // Token cached so no need for second approval
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND);
            location = response.getHeaders().getLocation().toString();
        }
        assertThat(location).as("Wrong location: " + location).matches("http://redirect.uri" + ".*code=.+");

        formData.clear();
        formData.add("client_id", clientId);
        formData.add("redirect_uri", "http://redirect.uri");
        formData.add("grant_type", GRANT_TYPE_AUTHORIZATION_CODE);
        formData.add("code", location.split("code=")[1].split("&")[0]);
        HttpHeaders tokenHeaders = new HttpHeaders();
        tokenHeaders.set("Authorization", testAccounts.getAuthorizationHeader(clientId, clientSecret));
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> tokenResponse = serverRunning.postForMap("/oauth/token", formData, tokenHeaders);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        @SuppressWarnings("unchecked")
        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(tokenResponse.getBody());
        return accessToken;
    }
}
