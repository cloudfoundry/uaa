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
package org.cloudfoundry.identity.uaa.integration;

import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.assertj.core.api.Assertions;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.client.http.OAuth2ErrorHandler;
import org.cloudfoundry.identity.uaa.oauth.client.test.OAuth2ContextConfiguration;
import org.cloudfoundry.identity.uaa.oauth.client.test.OAuth2ContextSetup;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.*;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.crypto.codec.Base64;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.doesSupportZoneDNS;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.getHeaders;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.USER_OAUTH_APPROVAL;

@OAuth2ContextConfiguration(OAuth2ContextConfiguration.ClientCredentials.class)
public class ScimGroupEndpointsIntegrationTests {

    private ScimGroupMember DALE, JOEL, VIDYA;

    private final String DELETE_ME = "deleteme_" + new RandomValueStringGenerator().generate().toLowerCase();

    private final String CF_DEV = "cf_dev_" + new RandomValueStringGenerator().generate().toLowerCase();

    private final String CF_MGR = "cf_mgr_" + new RandomValueStringGenerator().generate().toLowerCase();

    private final String CFID = "cfid_" + new RandomValueStringGenerator().generate().toLowerCase();

    private final List<String> allowedGroups = List.of(DELETE_ME, CF_DEV, CF_MGR, CFID);

    private final String groupEndpoint = "/Groups";

    private final String userEndpoint = "/Users";

    private List<String> groupIds = new ArrayList<String>();

    private static final List<String> defaultGroups = Arrays.asList("openid", "scim.me", "cloud_controller.read",
            "cloud_controller.write", "password.write", "scim.userids", "uaa.user", "approvals.me",
            "oauth.approvals", "cloud_controller_service_permissions.read", "profile", "roles", "user_attributes", "uaa.offline_token");

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    @Rule
    public OAuth2ContextSetup context = OAuth2ContextSetup.withTestAccounts(serverRunning, testAccountSetup);


    private RestTemplate client;
    private List<ScimGroup> scimGroups;

    @Before
    public void createRestTemplate() {
        client = (RestTemplate) serverRunning.getRestTemplate();
        client.setErrorHandler(new OAuth2ErrorHandler(context.getResource()) {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) {
            }
        });

        JOEL = new ScimGroupMember(createUser("joel_" + new RandomValueStringGenerator().generate().toLowerCase(), "Passwo3d").getId());
        DALE = new ScimGroupMember(createUser("dale_" + new RandomValueStringGenerator().generate().toLowerCase(), "Passwo3d").getId());
        VIDYA = new ScimGroupMember(createUser("vidya_" + new RandomValueStringGenerator().generate().toLowerCase(), "Passwo3d").getId());
    }

    @After
    public void tearDown() {
        deleteResource(userEndpoint, DALE.getMemberId());
        deleteResource(userEndpoint, JOEL.getMemberId());
        deleteResource(userEndpoint, VIDYA.getMemberId());
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
        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.setName(new ScimUser.Name(username, username));
        user.addEmail(username);
        user.setVerified(true);
        user.setPassword(password);
        ResponseEntity<ScimUser> result = client.postForEntity(serverRunning.getUrl(userEndpoint), user, ScimUser.class);
        assertEquals(HttpStatus.CREATED, result.getStatusCode());
        return result.getBody();
    }

    private ScimGroup createGroup(String name, ScimGroupMember... members) {
        ScimGroup g = new ScimGroup(null, name, IdentityZoneHolder.get().getId());
        List<ScimGroupMember> m = members != null ? Arrays.asList(members) : Collections.emptyList();
        g.setMembers(m);
        ScimGroup g1 = client.postForEntity(serverRunning.getUrl(groupEndpoint), g, ScimGroup.class).getBody();
        assertEquals(name, g1.getDisplayName());
        assertEquals(m.size(), g1.getMembers().size());
        groupIds.add(g1.getId());
        return g1;
    }

    private ScimGroup updateGroup(String id, String name, ScimGroupMember... members) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("If-Match", "*");
        ScimGroup g = new ScimGroup(null, name, IdentityZoneHolder.get().getId());
        List<ScimGroupMember> m = members != null ? Arrays.asList(members) : Collections.emptyList();
        g.setMembers(m);
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> r = client.exchange(serverRunning.getUrl(groupEndpoint + "/{id}"), HttpMethod.PUT,
                new HttpEntity<>(g, headers), Map.class, id);
        ScimGroup g1 = client.exchange(serverRunning.getUrl(groupEndpoint + "/{id}"), HttpMethod.PUT,
                new HttpEntity<>(g, headers), ScimGroup.class, id).getBody();
        assertEquals(name, g1.getDisplayName());
        assertEquals(m.size(), g1.getMembers().size());
        return g1;
    }

    private void validateUserGroups(String id, String... groups) {
        List<String> groupNames = groups != null ? Arrays.asList(groups) : Collections.emptyList();
        assertEquals(groupNames.size() + defaultGroups.size(), getUser(id).getGroups().size());
        for (ScimUser.Group g : getUser(id).getGroups()) {
            assertTrue(defaultGroups.contains(g.getDisplay()) || groupNames.contains(g.getDisplay()));
        }
    }

    private ScimUser getUser(String id) {
        return client.getForEntity(serverRunning.getUrl(userEndpoint + "/{id}"), ScimUser.class, id).getBody();
    }

    @Test
    public void getGroupsWithoutAttributesReturnsAllData() {
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = client.getForEntity(serverRunning.getUrl(groupEndpoint), Map.class);

        @SuppressWarnings("rawtypes")
        Map results = response.getBody();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue("There should be more than zero users", (Integer) results.get("totalResults") > 0);
        assertTrue("There should be some resources", ((Collection<?>) results.get("resources")).size() > 0);
        @SuppressWarnings("rawtypes")
        Map firstGroup = (Map) ((List) results.get("resources")).get(0);
        assertTrue(firstGroup.containsKey("id"));
        assertTrue(firstGroup.containsKey("displayName"));
        assertTrue(firstGroup.containsKey("schemas"));
        assertTrue(firstGroup.containsKey("meta"));
    }

    @Test
    public void createGroupSucceeds() {
        ScimGroup g1 = createGroup(CFID);
        // Check we can GET the group
        ScimGroup g2 = client.getForObject(serverRunning.getUrl(groupEndpoint + "/{id}"), ScimGroup.class, g1.getId());
        assertEquals(g1, g2);
    }

    @Test
    public void createAllowedGroupSucceeds() throws URISyntaxException {
        String testZoneId = "testzone1";
        assertTrue("Expected testzone1.localhost and testzone2.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());
        String adminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning.getBaseUrl(), "admin", "adminsecret");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.getUserConfig().setAllowedGroups(allowedGroups);
        String zoneUrl = serverRunning.getBaseUrl().replace("localhost", testZoneId + ".localhost");
        String inZoneAdminToken = IntegrationTestUtils.createClientAdminTokenInZone(serverRunning.getBaseUrl(), adminToken, testZoneId, config);
        ScimGroup g1 = new ScimGroup(null, CFID, testZoneId);
        // Check we can GET the group
        ScimGroup g2 = IntegrationTestUtils.createOrUpdateGroup(inZoneAdminToken, null, zoneUrl, g1);
        assertEquals(g1.getDisplayName(), g2.getDisplayName());
        assertEquals(g1.getDisplayName(), IntegrationTestUtils.getGroup(inZoneAdminToken, null, zoneUrl, g1.getDisplayName()).getDisplayName());
        IntegrationTestUtils.deleteZone(serverRunning.getBaseUrl(), testZoneId, adminToken);
    }

    @Test
    public void createNotAllowedGroupFailsCorrectly() throws URISyntaxException {
        String testZoneId = "testzone1";
        assertTrue("Expected testzone1.localhost and testzone2.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());
        final String NOT_ALLOWED = "not_allowed_" + new RandomValueStringGenerator().generate().toLowerCase();
        String adminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning.getBaseUrl(), "admin", "adminsecret");
        ScimGroup g1 = new ScimGroup(null, NOT_ALLOWED, testZoneId);
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
            assertTrue(e.getStatusCode().is4xxClientError());
            assertEquals(400, e.getRawStatusCode());
            assertThat(e.getMessage(),
                containsString("The group with displayName: "+ g1.getDisplayName() +" is not allowed in Identity Zone " + testZoneId));
        } finally {
            IntegrationTestUtils.deleteZone(serverRunning.getBaseUrl(), testZoneId, adminToken);
        }
    }

    @Test
    public void relyOnDefaultGroupsShouldAllowedGroupSucceed() throws URISyntaxException {
        String testZoneId = "testzone1";
        assertTrue("Expected testzone1.localhost and testzone2.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());
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
        assertNotNull(ccGroupFromGetCall);
        assertEquals(ccReadGroupName, ccGroupFromGetCall.getDisplayName());

        IntegrationTestUtils.deleteZone(serverRunning.getBaseUrl(), testZoneId, adminToken);
    }

    @Test
    public void changeDefaultGroupsAllowedGroupsUsageShouldSucceed() throws URISyntaxException {
        String testZoneId = "testzone1";
        assertTrue("Expected testzone1.localhost and testzone2.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());
        String adminToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning.getBaseUrl(), "admin", "adminsecret");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();

        // ensure zone does not exist
        if (IntegrationTestUtils.zoneExists(serverRunning.getBaseUrl(), testZoneId, adminToken)) {
            IntegrationTestUtils.deleteZone(serverRunning.getBaseUrl(), testZoneId, adminToken);
        }

        // add a new group to the allowed groups
        final String ALLOWED = "allowed_" + new RandomValueStringGenerator().generate().toLowerCase();
        List<String> newDefaultGroups = new ArrayList<String>(defaultGroups);
        newDefaultGroups.add(ALLOWED);
        config.getUserConfig().setAllowedGroups(List.of());
        config.getUserConfig().setDefaultGroups(newDefaultGroups);
        String zoneUrl = serverRunning.getBaseUrl().replace("localhost", testZoneId + ".localhost");
        // this creates the zone as well as all default groups
        String inZoneAdminToken = IntegrationTestUtils.createClientAdminTokenInZone(serverRunning.getBaseUrl(), adminToken, testZoneId, config);

        // creating the newly allowed group should fail, as it already exists
        RestTemplate template = new RestTemplate();
        ScimGroup g1 = new ScimGroup(null, ALLOWED, testZoneId);
        HttpEntity entity = new HttpEntity<>(JsonUtils.writeValueAsBytes(g1), IntegrationTestUtils.getAuthenticatedHeaders(inZoneAdminToken));
        try {
            final HttpClientErrorException.Conflict exception = assertThrows(
                    HttpClientErrorException.Conflict.class,
                    () -> template.exchange(zoneUrl + "/Groups", HttpMethod.POST, entity, HashMap.class)
            );
            Assertions.assertThat(exception.getMessage())
                    .contains("A group with displayName: %s already exists.".formatted(ALLOWED));
        } finally {
            IntegrationTestUtils.deleteZone(serverRunning.getBaseUrl(), testZoneId, adminToken);
        }
    }

    @Test
    public void createGroupWithMembersSucceeds() {
        ScimGroup g1 = createGroup(CFID, JOEL, DALE, VIDYA);
        // Check we can GET the group
        ScimGroup g2 = client.getForObject(serverRunning.getUrl(groupEndpoint + "/{id}"), ScimGroup.class, g1.getId());
        assertEquals(g1, g2);
        assertEquals(3, g2.getMembers().size());
        assertTrue(g2.getMembers().contains(JOEL));
        assertTrue(g2.getMembers().contains(DALE));
        assertTrue(g2.getMembers().contains(VIDYA));

        // check that User.groups is updated
        validateUserGroups(JOEL.getMemberId(), CFID);
        validateUserGroups(DALE.getMemberId(), CFID);
        validateUserGroups(VIDYA.getMemberId(), CFID);
    }

    @Test
    public void createGroupWithInvalidMembersFailsCorrectly() {
        ScimGroup g = new ScimGroup(null, CFID, IdentityZoneHolder.get().getId());
        ScimGroupMember m2 = new ScimGroupMember("wrongid");
        g.setMembers(Arrays.asList(VIDYA, m2));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> r = client.postForEntity(serverRunning.getUrl(groupEndpoint), g, Map.class);
        @SuppressWarnings("unchecked")
        Map<String, String> g1 = r.getBody();
        assertEquals(HttpStatus.BAD_REQUEST, r.getStatusCode());
        assertTrue(g1.containsKey("error"));
        assertTrue(g1.containsKey("message"));
        assertTrue(g1.get("message").contains("Invalid group member"));

        // check that the group was not created
        @SuppressWarnings("unchecked")
        Map<String, Object> g2 = client.getForObject(
                serverRunning.getUrl(groupEndpoint + "?filter=displayName eq \"{name}\""), Map.class, CFID);
        assertTrue(g2.containsKey("totalResults"));
        assertEquals(Integer.valueOf(0), (Integer) g2.get("totalResults"));
    }

    @Test
    public void createGroupWithMemberGroupSucceeds() {
        ScimGroup g1 = createGroup(CFID, VIDYA);
        ScimGroupMember m2 = new ScimGroupMember(g1.getId(), ScimGroupMember.Type.GROUP);
        ScimGroup g2 = createGroup(CF_DEV, m2);

        // Check we can GET the group
        ScimGroup g3 = client.getForObject(serverRunning.getUrl(groupEndpoint + "/{id}"), ScimGroup.class, g2.getId());
        assertEquals(g2, g3);
        assertEquals(1, g3.getMembers().size());
        assertTrue(g3.getMembers().contains(m2));

        // check that User.groups is updated
        validateUserGroups(VIDYA.getMemberId(), CFID, CF_DEV);
    }

    @Test
    public void createExistingGroupFailsCorrectly() {
        ScimGroup g1 = createGroup(CFID);
        @SuppressWarnings("unchecked")
        Map<String, String> g2 = client.postForEntity(serverRunning.getUrl(groupEndpoint), g1, Map.class).getBody();
        assertTrue(g2.containsKey("error"));
        assertEquals("scim_resource_already_exists", g2.get("error"));
    }

    @Test
    public void deleteGroupUpdatesUser() {
        ScimGroup g1 = createGroup(DELETE_ME, DALE, VIDYA);
        validateUserGroups(DALE.getMemberId(), DELETE_ME);
        validateUserGroups(VIDYA.getMemberId(), DELETE_ME);

        deleteResource(groupEndpoint, g1.getId());

        // check that the group does not exist anymore
        @SuppressWarnings("unchecked")
        Map<String, Object> g2 = client.getForObject(
                serverRunning.getUrl(groupEndpoint + "?filter=displayName eq \"{name}\""), Map.class, DELETE_ME);
        assertTrue(g2.containsKey("totalResults"));
        assertEquals(0, g2.get("totalResults"));

        // check that group membership is updated
        validateUserGroups(DALE.getMemberId());
        validateUserGroups(VIDYA.getMemberId());
    }

    @Test
    public void deleteNonExistentGroupFailsCorrectly() {
        @SuppressWarnings("unchecked")
        Map<String, Object> g = deleteResource(groupEndpoint, DELETE_ME).getBody();
        assertTrue(g.containsKey("error"));
        assertEquals("scim_resource_not_found", g.get("error"));
    }

    @Test
    public void deleteMemberGroupUpdatesGroup() {
        ScimGroup g1 = createGroup(CFID, VIDYA);
        ScimGroupMember m2 = new ScimGroupMember(g1.getId(), ScimGroupMember.Type.GROUP);
        ScimGroup g2 = createGroup(CF_DEV, DALE, m2);
        assertTrue(g2.getMembers().contains(m2));
        validateUserGroups(VIDYA.getMemberId(), CFID, CF_DEV);

        deleteResource(groupEndpoint, g1.getId());

        // check that parent group is updated
        ScimGroup g3 = client.getForObject(serverRunning.getUrl(groupEndpoint + "/{id}"), ScimGroup.class, g2.getId());
        assertEquals(1, g3.getMembers().size());
        assertFalse(g3.getMembers().contains(m2));
    }

    @Test
    public void testDeleteMemberUserUpdatesGroups() {
        ScimGroupMember toDelete = new ScimGroupMember(createUser(DELETE_ME, "Passwo3d").getId());
        ScimGroup g1 = createGroup(CFID, JOEL, DALE, toDelete);
        ScimGroup g2 = createGroup(CF_MGR, DALE, toDelete);
        deleteResource(userEndpoint, toDelete.getMemberId());

        // check that membership has been updated
        ScimGroup g3 = client.getForObject(serverRunning.getUrl(groupEndpoint + "/{id}"), ScimGroup.class, g1.getId());
        assertEquals(2, g3.getMembers().size());
        assertFalse(g3.getMembers().contains(toDelete));

        g3 = client.getForObject(serverRunning.getUrl(groupEndpoint + "/{id}"), ScimGroup.class, g2.getId());
        assertEquals(1, g3.getMembers().size());
        assertFalse(g3.getMembers().contains(toDelete));
    }

    @Test
    public void testUpdateGroupUpdatesMemberUsers() {
        ScimGroup g1 = createGroup(CFID, JOEL, VIDYA);
        ScimGroup g2 = createGroup(CF_MGR, DALE);
        ScimGroupMember m1 = new ScimGroupMember(g1.getId(), ScimGroupMember.Type.GROUP);
        ScimGroupMember m2 = new ScimGroupMember(g2.getId(), ScimGroupMember.Type.GROUP);
        ScimGroup g3 = createGroup(CF_DEV, m1, m2);

        validateUserGroups(JOEL.getMemberId(), CFID, CF_DEV);
        validateUserGroups(VIDYA.getMemberId(), CFID, CF_DEV);
        validateUserGroups(DALE.getMemberId(), CF_MGR, CF_DEV);

        ScimGroup g4 = updateGroup(g3.getId(), "new_name", m1);

        // check that we did not create a new group, but only updated the
        // existing one
        assertEquals(g3, g4);
        // check that member users were updated
        validateUserGroups(DALE.getMemberId(), CF_MGR);
        validateUserGroups(JOEL.getMemberId(), CFID, "new_name");
        validateUserGroups(VIDYA.getMemberId(), CFID, "new_name");
    }

    @Test
    public void testAccessTokenReflectsGroupMembership() throws Exception {

        createTestClient(DELETE_ME, "secret", CFID);
        ScimUser user = createUser(DELETE_ME, "Passwo3d");
        createGroup(CFID, new ScimGroupMember(user.getId()));
        OAuth2AccessToken token = getAccessToken(DELETE_ME, "secret", DELETE_ME, "Passwo3d");
        assertTrue("Wrong token: " + token, token.getScope().contains(CFID));

        deleteTestClient(DELETE_ME);
        deleteResource(userEndpoint, user.getId());

    }

    @Test
    public void testAccessTokenReflectsGroupMembershipForPasswordGrant() throws Exception {

        createTestClient(DELETE_ME, "secret", CFID);
        ScimUser user = createUser(DELETE_ME, "Passwo3d");
        createGroup(CFID, new ScimGroupMember(user.getId()));
        OAuth2AccessToken token = getAccessTokenWithPassword(DELETE_ME, "secret", DELETE_ME, "Passwo3d");
        assertTrue("Wrong token: " + token, token.getScope().contains(CFID));

        deleteTestClient(DELETE_ME);
        deleteResource(userEndpoint, user.getId());

    }

    @Before
    public void initScimGroups() {
        scimGroups = new ArrayList<>();
    }

    @After
    public void teardownScimGroups() {
        for (ScimGroup scimGroup : scimGroups) {
            deleteResource(groupEndpoint, scimGroup.getId());
        }
    }

    @Test
    public void testExtremeGroupPagination() {
        for (int i = 0; i < 502; i++) {
            ScimUser user = createUser("deleteme_" + new RandomValueStringGenerator().generate().toLowerCase(), "Passwo3d");
            scimGroups.add(createGroup("cfid_" + new RandomValueStringGenerator().generate().toLowerCase(), new ScimGroupMember(user.getId())));
        }

        ResponseEntity<Map> response = client.getForEntity(serverRunning.getUrl(groupEndpoint + "?count=502"), Map.class);

        Map results = response.getBody();
        assertThat(response.getStatusCode(), is(HttpStatus.OK));
        assertThat((Integer) results.get("totalResults"), greaterThan(500));
        assertThat((List<?>) results.get("resources"), hasSize(500));
        assertThat(results.get("itemsPerPage"), is(500));
        assertThat(results.get("startIndex"), is(1));

    }

    private void createTestClient(String name, String secret, String scope) {
        OAuth2AccessToken token = getClientCredentialsAccessToken("clients.read,clients.write,clients.admin");
        HttpHeaders headers = getAuthenticatedHeaders(token);
        UaaClientDetails client = new UaaClientDetails(name, "", scope, "authorization_code,password",
                "scim.read,scim.write", "http://redirect.uri");
        client.setClientSecret(secret);
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
                HttpMethod.POST, new HttpEntity<>(client, headers), Void.class);
        assertEquals(HttpStatus.CREATED, result.getStatusCode());
    }

    private void deleteTestClient(String clientId) {
        OAuth2AccessToken token = getClientCredentialsAccessToken("clients.read,clients.write");
        HttpHeaders headers = getAuthenticatedHeaders(token);
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients/{client}"), HttpMethod.DELETE,
                new HttpEntity<Void>(headers),
                Void.class, clientId);
        assertEquals(HttpStatus.OK, result.getStatusCode());
    }

    private OAuth2AccessToken getClientCredentialsAccessToken(String scope) {

        String clientId = testAccounts.getAdminClientId();
        String clientSecret = testAccounts.getAdminClientSecret();

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add("grant_type", "client_credentials");
        formData.add("client_id", clientId);
        formData.add("scope", scope);
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.set("Authorization",
                "Basic " + new String(Base64.encode(String.format("%s:%s", clientId, clientSecret).getBytes())));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap("/oauth/token", formData, headers);
        assertEquals(HttpStatus.OK, response.getStatusCode());

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
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add("client_id", clientId);
        formData.add("grant_type", "password");
        formData.add("username", username);
        formData.add("password", password);
        HttpHeaders tokenHeaders = new HttpHeaders();
        tokenHeaders.set("Authorization", testAccounts.getAuthorizationHeader(clientId, clientSecret));
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> tokenResponse = serverRunning.postForMap("/oauth/token", formData, tokenHeaders);
        assertEquals(HttpStatus.OK, tokenResponse.getStatusCode());
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
        assertEquals(HttpStatus.FOUND, result.getStatusCode());
        String location = result.getHeaders().getLocation().toString();

        if (result.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : result.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength + 1)));
            }
        }

        ResponseEntity<String> response = serverRunning.getForString(location, getHeaders(cookies));
        // should be directed to the login screen...
        assertTrue(response.getBody().contains("/login.do"));
        assertTrue(response.getBody().contains("username"));
        assertTrue(response.getBody().contains("password"));

        if (response.getHeaders().containsKey("Set-Cookie")) {
            String cookie = response.getHeaders().getFirst("Set-Cookie");
            int nameLength = cookie.indexOf('=');
            cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength + 1)));
        }

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("username", username);
        formData.add("password", password);
        formData.add(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(response.getBody()));

        // Should be redirected to the original URL, but now authenticated
        result = serverRunning.postForResponse("/login.do", getHeaders(cookies), formData);
        assertEquals(HttpStatus.FOUND, result.getStatusCode());

        cookies.clear();
        if (result.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : result.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength + 1)));
            }
        }

        response = serverRunning.createRestTemplate().exchange(
                new URI(result.getHeaders().getLocation().toString()),
                HttpMethod.GET,
                new HttpEntity<>(null, getHeaders(cookies)),
                String.class);
        if (response.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : response.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength + 1)));
            }
        }
        if (response.getStatusCode() == HttpStatus.OK) {
            // The grant access page should be returned
            assertTrue(response.getBody().contains("<h1>Application Authorization</h1>"));

            formData.clear();
            formData.add(DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(response.getBody()));
            formData.add(USER_OAUTH_APPROVAL, "true");
            formData.add("scope.0", "scope." + CFID);
            result = serverRunning.postForResponse("/oauth/authorize", getHeaders(cookies), formData);
            assertEquals(HttpStatus.FOUND, result.getStatusCode());
            location = result.getHeaders().getLocation().toString();
        } else {
            // Token cached so no need for second approval
            assertEquals(HttpStatus.FOUND, response.getStatusCode());
            location = response.getHeaders().getLocation().toString();
        }
        assertTrue("Wrong location: " + location, location.matches("http://redirect.uri" + ".*code=.+"));

        formData.clear();
        formData.add("client_id", clientId);
        formData.add("redirect_uri", "http://redirect.uri");
        formData.add("grant_type", GRANT_TYPE_AUTHORIZATION_CODE);
        formData.add("code", location.split("code=")[1].split("&")[0]);
        HttpHeaders tokenHeaders = new HttpHeaders();
        tokenHeaders.set("Authorization", testAccounts.getAuthorizationHeader(clientId, clientSecret));
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> tokenResponse = serverRunning.postForMap("/oauth/token", formData, tokenHeaders);
        assertEquals(HttpStatus.OK, tokenResponse.getStatusCode());
        @SuppressWarnings("unchecked")
        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(tokenResponse.getBody());
        return accessToken;
    }

}