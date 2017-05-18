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
package org.cloudfoundry.identity.uaa.scim.endpoints;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.bootstrap.ScimExternalGroupBootstrap;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.ZoneManagementScopes;
import org.hamcrest.Matcher;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.utils;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.util.StringUtils.hasText;

public class ScimGroupEndpointsMockMvcTests extends InjectedMockContextTest {

    private static List<String> originalDefaultExternalMembers;
    private static List<ScimGroupExternalMember> originalDatabaseExternalMembers;

    private String scimReadToken;
    private String scimWriteToken;
    private String scimReadUserToken;
    private String identityClientToken;
    private ScimUser scimUser;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private List<String> defaultExternalMembers;
    private List<ScimGroupExternalMember> databaseExternalMembers;
    private String clientId;
    private String clientSecret;
    private JdbcTemplate template;
    private ScimExternalGroupBootstrap bootstrap;

    private ArrayList<String[]> ephemeralResources = new ArrayList<>();

    @Before
    public void setUp() throws Exception {
        if (originalDatabaseExternalMembers==null) {
            originalDefaultExternalMembers = (List<String>) getWebApplicationContext().getBean("defaultExternalMembers");
            originalDatabaseExternalMembers = getWebApplicationContext().getBean(JdbcScimGroupExternalMembershipManager.class).query("");
        }

        if(bootstrap == null){
            bootstrap = getWebApplicationContext().getBean(ScimExternalGroupBootstrap.class);
        }

        if(template == null) {
            template = getWebApplicationContext().getBean(JdbcTemplate.class);
        }

        template.update("delete from external_group_mapping");
        bootstrap.afterPropertiesSet();

        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret",
                "clients.read clients.write clients.secret clients.admin");
        clientId = generator.generate().toLowerCase();
        clientSecret = generator.generate().toLowerCase();
        String authorities = "scim.read,scim.write,password.write,oauth.approvals,scim.create,other.scope";
        utils().createClient(this.getMockMvc(), adminToken, clientId, clientSecret, Collections.singleton("oauth"), Arrays.asList("foo","bar","scim.read"), Arrays.asList("client_credentials", "password"), authorities);
        scimReadToken = testClient.getClientCredentialsOAuthAccessToken(clientId, clientSecret,"scim.read password.write");
        scimWriteToken = testClient.getClientCredentialsOAuthAccessToken(clientId, clientSecret,"scim.write password.write");

        defaultExternalMembers = new LinkedList<>(originalDefaultExternalMembers);
        databaseExternalMembers = new LinkedList<>(originalDatabaseExternalMembers);

        scimUser = createUserAndAddToGroups(IdentityZone.getUaa(), new HashSet(Arrays.asList("scim.read", "scim.write", "scim.me")));
        scimReadUserToken = testClient.getUserOAuthAccessToken("cf","", scimUser.getUserName(), "password", "scim.read");
        identityClientToken = testClient.getClientCredentialsOAuthAccessToken("identity","identitysecret","");
    }

    @After
    public void cleanUp() {
        for(Object[] resource : ephemeralResources) {
            template.update("delete from group_membership where member_id = ? and member_type = ?", resource);
        }
        ephemeralResources.clear();
    }

    @Test
    public void testIdentityClientManagesZoneAdmins() throws Exception {
        IdentityZone zone = utils().createZoneUsingWebRequest(getMockMvc(), identityClientToken);
        ScimGroupMember member = new ScimGroupMember(scimUser.getId());
        ScimGroup group = new ScimGroup(null, "zones."+zone.getId()+".admin", zone.getId());
        group.setMembers(Arrays.asList(member));
        MockHttpServletRequestBuilder post = post("/Groups/zones")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .header("Authorization", "Bearer " + identityClientToken)
            .content(JsonUtils.writeValueAsBytes(group));
        //create the zones.{id}.admin
        getMockMvc().perform(post)
            .andExpect(status().isCreated());

        MockHttpServletRequestBuilder delete = delete("/Groups/zones/{userId}/{zoneId}", scimUser.getId(), zone.getId())
            .header("Authorization", "Bearer "+identityClientToken);
        //delete the zones.{id}.admin
        getMockMvc().perform(delete).andExpect(status().isOk());
        //the relationship is not found
        getMockMvc().perform(delete).andExpect(status().isNotFound());

        //try a regular scim token
        getMockMvc().perform(post("/Groups/zones")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .header("Authorization", "Bearer " + scimWriteToken)
            .content(JsonUtils.writeValueAsBytes(group)))
            .andExpect(status().isForbidden());

        getMockMvc().perform(
            delete("/Groups/zones/{userId}/{zoneId}", scimUser.getId(), zone.getId())
                .header("Authorization", "Bearer " + scimWriteToken))
            .andExpect(status().isForbidden());

        getMockMvc().perform(
            delete("/Groups/zones/{userId}/{zoneId}", "nonexistent", zone.getId())
                .header("Authorization", "Bearer " + identityClientToken))
            .andExpect(status().isNotFound());

        getMockMvc().perform(post("/Groups/zones")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .header("Authorization", "Bearer " + identityClientToken)
            .content(""))
            .andExpect(status().isBadRequest());

        //add two users to the same zone
        for (int i=0; i<2; i++) {
            ScimUser user = createUserAndAddToGroups(IdentityZone.getUaa(), new HashSet(Arrays.asList("scim.read", "scim.write", "scim.me")));
            member = new ScimGroupMember(user.getId());
            group = new ScimGroup(null, "zones."+zone.getId()+".admin", zone.getId());
            group.setMembers(Arrays.asList(member));

            post = post("/Groups/zones")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .header("Authorization", "Bearer " + identityClientToken)
                .content(JsonUtils.writeValueAsBytes(group));
            //create the zones.{id}.admin
            getMockMvc().perform(post)
                .andExpect(status().isCreated());
        }
    }

    @Test
    public void testLimitedScopesWithoutMember() throws Exception {
        IdentityZone zone = utils().createZoneUsingWebRequest(getMockMvc(), identityClientToken);
        ScimGroup group = new ScimGroup("zones." + zone.getId() + ".admin");

        MockHttpServletRequestBuilder post = post("/Groups/zones")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .header("Authorization", "Bearer " + identityClientToken)
            .content(JsonUtils.writeValueAsBytes(group));

        getMockMvc().perform(post)
            .andExpect(status().isBadRequest());
    }

    @Test
    public void add_and_Delete_Members_toZoneManagementGroups_withVariousGroupNames() throws Exception {
        addAndDeleteMemberstoZoneManagementGroups("zones.%s.admin", HttpStatus.CREATED, HttpStatus.OK);
        addAndDeleteMemberstoZoneManagementGroups("zones.%s.read", HttpStatus.CREATED, HttpStatus.OK);
        addAndDeleteMemberstoZoneManagementGroups("zones.%s.clients.read", HttpStatus.CREATED, HttpStatus.OK);
        addAndDeleteMemberstoZoneManagementGroups("zones.%s.clients.write", HttpStatus.CREATED, HttpStatus.OK);
        addAndDeleteMemberstoZoneManagementGroups("zones.%s.clients.admin", HttpStatus.CREATED, HttpStatus.OK);
        addAndDeleteMemberstoZoneManagementGroups("zones.%s.idps.read", HttpStatus.CREATED, HttpStatus.OK);

        addAndDeleteMemberstoZoneManagementGroups("zones.%s.blah.clients.read", HttpStatus.BAD_REQUEST, null);
        addAndDeleteMemberstoZoneManagementGroups("zones.%s.invalid", HttpStatus.BAD_REQUEST, null);

        addAndDeleteMemberstoZoneManagementGroups("zones..admin", HttpStatus.BAD_REQUEST, null);
    }

    private ResultActions[] addAndDeleteMemberstoZoneManagementGroups(String displayName, HttpStatus create, HttpStatus delete) throws Exception {
        ResultActions[] result = new  ResultActions[2];
        IdentityZone zone = utils().createZoneUsingWebRequest(getMockMvc(), identityClientToken);
        ScimGroupMember member = new ScimGroupMember(scimUser.getId());
        ScimGroup group = new ScimGroup(String.format(displayName, zone.getId()));
        group.setMembers(Arrays.asList(member));

        result[0] = createZoneScope(group);
        result[0].andExpect(status().is(create.value()));

        if (delete!=null ) {
            result[1] = deleteZoneScope(zone, group);
            result[1].andExpect(status().is(delete.value()));
        }
        return result;
    }

    private ResultActions deleteZoneScope(IdentityZone zone, ScimGroup group) throws Exception {
        String removeS = String.format("zones.%s.", zone.getId());
        String scope = group.getDisplayName().substring(removeS.length());
        MockHttpServletRequestBuilder delete = delete("/Groups/zones/{userId}/{zoneId}/{scope}", scimUser.getId(), zone.getId(), scope)
            .accept(APPLICATION_JSON)
            .header("Authorization", "Bearer " + identityClientToken);
        return getMockMvc().perform(delete);
    }

    private ResultActions createZoneScope(ScimGroup group) throws Exception {
        MockHttpServletRequestBuilder post = post("/Groups/zones")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .header("Authorization", "Bearer " + identityClientToken)
            .content(JsonUtils.writeValueAsBytes(group));
        return getMockMvc().perform(post);
    }

    @Test
    public void testGroupOperations_as_Zone_Admin() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = utils().createOtherIdentityZoneAndReturnResult(subdomain, getMockMvc(), getWebApplicationContext(), null);
        String zoneAdminToken = result.getZoneAdminToken();
        IdentityZone zone = result.getIdentityZone();

        String groupName = generator.generate();
        String headerName = IdentityZoneSwitchingFilter.HEADER;
        String headerValue = zone.getId();

        ScimGroup group = new ScimGroup(null,groupName,null);

        MockHttpServletRequestBuilder create = post("/Groups")
            .header(headerName, headerValue)
            .header("Authorization", "bearer "+zoneAdminToken)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(group));

        group = JsonUtils.readValue(
                getMockMvc().perform(create)
                    .andExpect(status().isCreated())
                    .andReturn().getResponse().getContentAsString(),
                ScimGroup.class);

        MockHttpServletRequestBuilder update = put("/Groups/" + group.getId())
            .header(headerName, headerValue)
            .header("Authorization", "bearer "+zoneAdminToken)
            .header("If-Match", group.getVersion())
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(group));

        group = JsonUtils.readValue(
            getMockMvc().perform(update)
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(),
            ScimGroup.class);

        MockHttpServletRequestBuilder get = get("/Groups/" + group.getId())
            .header(headerName, headerValue)
            .header("Authorization", "bearer " + zoneAdminToken)
            .accept(APPLICATION_JSON);

        assertEquals(group, JsonUtils.readValue(
            getMockMvc().perform(get)
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(),
            ScimGroup.class));
    }

//    @Test
//    @Ignore //we only create DB once - so can no longer run
//    public void testDBisDownDuringCreate() throws Exception {
//        for (String s  : getWebApplicationContext().getEnvironment().getActiveProfiles()) {
//            Assume.assumeFalse("Does not run during MySQL", "mysql".equals(s));
//            Assume.assumeFalse("Does not run during PostgreSQL", "postgresql".equals(s));
//        }
//        String externalGroup = "cn=developers,ou=scopes,dc=test,dc=com";
//        String displayName ="internal.read";
//        DataSource ds = getWebApplicationContext().getBean(DataSource.class);
//        new JdbcTemplate(ds).execute("SHUTDOWN");
//        Method close = ds.getClass().getMethod("close");
//        Assert.assertNotNull(close);
//        close.invoke(ds);
//        ResultActions result = createGroup(null, displayName, externalGroup);
//        result.andExpect(status().isServiceUnavailable());
//    }

    @Test
    public void getGroups_withScimReadTokens_returnsOkWithResults() throws Exception {
        String filterNarrow = "displayName eq \"clients.read\" or displayName eq \"clients.write\"";
        String filterWide = "displayName eq \"clients.read\" or displayName eq \"clients.write\" or displayName eq \"zones.read\" or displayName eq \"zones.write\"";

        MockHttpServletRequestBuilder get = get("/Groups")
            .header("Authorization", "Bearer " + scimReadToken)
            .param("attributes", "displayName")
            .param("filter", filterNarrow)
            .contentType(MediaType.APPLICATION_JSON)
            .accept(APPLICATION_JSON);
        MvcResult mvcResult = getMockMvc().perform(get)
                .andExpect(status().isOk())
                .andReturn();

        String body = mvcResult.getResponse().getContentAsString();
        SearchResults<ScimGroup> searchResults = JsonUtils.readValue(body, SearchResults.class);
        assertThat("Search results: " + body, searchResults.getResources(), hasSize(2));

        get = get("/Groups")
            .header("Authorization", "Bearer " + scimReadUserToken)
            .param("attributes", "displayName")
            .param("filter", filterNarrow)
            .contentType(MediaType.APPLICATION_JSON)
            .accept(APPLICATION_JSON);
        mvcResult = getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andReturn();

        body = mvcResult.getResponse().getContentAsString();
        searchResults = JsonUtils.readValue(body, SearchResults.class);
        assertThat("Search results: " + body, searchResults.getResources(), hasSize(2));

        get = get("/Groups")
            .header("Authorization", "Bearer " + scimReadToken)
            .contentType(MediaType.APPLICATION_JSON)
                .param("filter", filterWide)
            .accept(APPLICATION_JSON);
        mvcResult = getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andReturn();

        body = mvcResult.getResponse().getContentAsString();
        searchResults = JsonUtils.readValue(body, SearchResults.class);
        assertThat("Search results: " + body, searchResults.getResources(), hasSize(4));

        get = get("/Groups")
            .header("Authorization", "Bearer " + scimReadUserToken)
            .contentType(MediaType.APPLICATION_JSON)
                .param("filter", filterWide)
            .accept(APPLICATION_JSON);
        mvcResult = getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andReturn();

        body = mvcResult.getResponse().getContentAsString();
        searchResults = JsonUtils.readValue(body, SearchResults.class);
        assertThat("Search results: " + body, searchResults.getResources(), hasSize(4));
    }

    @Test
    public void getGroupsInOtherZone_withZoneAdminToken_returnsOkWithResults() throws Exception {
        String subdomain = new RandomValueStringGenerator(8).generate();
        BaseClientDetails bootstrapClient = null;
        MockMvcUtils.IdentityZoneCreationResult result = utils().createOtherIdentityZoneAndReturnResult(
            subdomain, getMockMvc(), getWebApplicationContext(), bootstrapClient
        );

        ScimGroup group1 = new ScimGroup(null, "scim.whatever", result.getIdentityZone().getId());
        ScimGroup group2 = new ScimGroup(null, "another.group", result.getIdentityZone().getId());

        getMockMvc().perform(post("/Groups")
                .header(IdentityZoneSwitchingFilter.HEADER, result.getIdentityZone().getId())
                .header("Authorization", "bearer "+ result.getZoneAdminToken())
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(group1)))
                .andExpect(status().isCreated());

        getMockMvc().perform(post("/Groups")
                .header(IdentityZoneSwitchingFilter.HEADER, result.getIdentityZone().getId())
                .header("Authorization", "bearer "+result.getZoneAdminToken())
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(group2)))
                .andExpect(status().isCreated());

        MockHttpServletRequestBuilder get = get("/Groups")
            .header("Authorization", "Bearer " + result.getZoneAdminToken())
            .header(IdentityZoneSwitchingFilter.HEADER, result.getIdentityZone().getId())
            .param("attributes", "displayName")
            .param("filter", "displayName co \"scim\"")
            .contentType(MediaType.APPLICATION_JSON)
            .accept(APPLICATION_JSON);
        MvcResult mvcResult = getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andReturn();

        SearchResults searchResults = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), SearchResults.class);
        assertThat(searchResults.getResources().size(), is(getSystemScopes("scim").size()+1));

        get = get("/Groups")
            .header("Authorization", "Bearer " + result.getZoneAdminToken())
            .header(IdentityZoneSwitchingFilter.HEADER, result.getIdentityZone().getId())
            .contentType(MediaType.APPLICATION_JSON)
            .accept(APPLICATION_JSON);
        mvcResult = getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andReturn();

        searchResults = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), SearchResults.class);
        assertThat(searchResults.getResources().size(), is(getSystemScopes(null).size()+2));
    }

    protected List<String> getSystemScopes(String containing) {
        List<String> systemScopes = ZoneManagementScopes.getSystemScopes();
        if (hasText(containing)) {
            return systemScopes.stream().filter(s -> s.contains(containing)).collect(Collectors.toList());
        } else {
            return systemScopes;
        }
    }

    @Test
    public void getGroupsInOtherZone_withZoneUserToken_returnsOkWithResults() throws Exception{
        String subdomain = new RandomValueStringGenerator(8).generate();
        BaseClientDetails bootstrapClient = null;
        MockMvcUtils.IdentityZoneCreationResult result = utils().createOtherIdentityZoneAndReturnResult(
            subdomain, getMockMvc(), getWebApplicationContext(), bootstrapClient
        );

        String zonedClientId = "zonedClientId";
        String zonedClientSecret = "zonedClientSecret";
        BaseClientDetails zonedClientDetails = (BaseClientDetails) utils().createClient(getMockMvc(), result.getZoneAdminToken(), zonedClientId, zonedClientSecret, Collections.singleton("oauth"), Arrays.asList("scim.read"), Arrays.asList("client_credentials", "password"), "scim.read", null, result.getIdentityZone());
        zonedClientDetails.setClientSecret(zonedClientSecret);

        ScimUser zoneUser = createUserAndAddToGroups(result.getIdentityZone(), new HashSet(Arrays.asList("scim.read")));

        String basicDigestHeaderValue = "Basic " + new String(Base64.encodeBase64((zonedClientId + ":" + zonedClientSecret).getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .with(new SetServerNameRequestPostProcessor(result.getIdentityZone().getSubdomain() + ".localhost"))
                .header("Authorization", basicDigestHeaderValue)
                .param("grant_type", "password")
                .param("client_id", zonedClientId)
                .param("username", zoneUser.getUserName())
                .param("password", "password")
                .param("scope", "scim.read");
        MvcResult tokenResult = getMockMvc().perform(oauthTokenPost).andExpect(status().isOk()).andReturn();
        OAuthToken oauthToken = JsonUtils.readValue(tokenResult.getResponse().getContentAsString(), OAuthToken.class);
        String zoneUserToken = oauthToken.accessToken;

        MockHttpServletRequestBuilder get = get("/Groups")
                .with(new SetServerNameRequestPostProcessor(result.getIdentityZone().getSubdomain() + ".localhost"))
                .header("Authorization", "Bearer " + zoneUserToken)
//                .header(IdentityZoneSwitchingFilter.HEADER, result.getIdentityZone().getId())
                .param("attributes", "displayName")
                .param("filter", "displayName co \"scim\"")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(APPLICATION_JSON);
        MvcResult mvcResult = getMockMvc().perform(get)
                .andExpect(status().isOk())
                .andReturn();

        SearchResults searchResults = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), SearchResults.class);
        assertThat(searchResults.getResources().size(), is(getSystemScopes("scim").size()));

        get = get("/Groups")
                .with(new SetServerNameRequestPostProcessor(result.getIdentityZone().getSubdomain() + ".localhost"))
                .header("Authorization", "Bearer " + zoneUserToken)
//                .header(IdentityZoneSwitchingFilter.HEADER, result.getIdentityZone().getId())
                .contentType(MediaType.APPLICATION_JSON)
                .accept(APPLICATION_JSON);
        mvcResult = getMockMvc().perform(get)
                .andExpect(status().isOk())
                .andReturn();

        searchResults = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), SearchResults.class);
        assertThat(searchResults.getResources().size(), is(getSystemScopes(null).size()));
    }

    @Test
    public void testGetGroupsInvalidFilter() throws Exception {
        MockHttpServletRequestBuilder get = get("/Groups")
                .header("Authorization", "Bearer " + scimReadToken)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .param("filter", "blabla eq \"test\"");

        getMockMvc().perform(get)
                .andExpect(status().isBadRequest());

        get = get("/Groups")
                .header("Authorization", "Bearer " + scimReadUserToken)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .param("filter", "blabla eq \"test\"");

        getMockMvc().perform(get)
                .andExpect(status().isBadRequest());
    }

    @Test
    public void testGetGroupsInvalidAttributes() throws Exception {
        String nonexistentAttribute = "displayBlaBla";

        MockHttpServletRequestBuilder get = get("/Groups")
          .header("Authorization", "Bearer " + scimReadToken)
          .contentType(MediaType.APPLICATION_JSON)
          .accept(APPLICATION_JSON)
          .param("attributes", nonexistentAttribute);

        MvcResult mvcResult = getMockMvc().perform(get)
          .andExpect(status().isOk())
          .andReturn();

        String body = mvcResult.getResponse().getContentAsString();
        List<Map> attList = (List) JsonUtils.readValue(body, Map.class).get("resources");
        for (Map<String, Object> attMap : attList) {
            assertNull(attMap.get(nonexistentAttribute));
        }
    }

    @Test
    public void testExternalGroupMembershipManagerNotNull() throws Exception {
        ScimGroupEndpoints sge = getWebApplicationContext().getBean(ScimGroupEndpoints.class);
        assertNotNull(sge.getExternalMembershipManager());
    }

    @Test
    public void testGetExternalGroups() throws Exception {
        checkGetExternalGroups();
    }

    @Test
    public void testCreateExternalGroupMapUsingName() throws Exception {
        String displayName ="internal.read";
        String externalGroup = "cn=java-developers,ou=scopes,dc=test,dc=com";
        ResultActions result = createGroup(null, displayName, externalGroup);
        result.andExpect(status().isCreated());

        //add the newly added list to our expected list, and check again.
        int previousSize = defaultExternalMembers.size();
        ArrayList<String> list = new ArrayList<>(defaultExternalMembers);
        list.add(displayName+"|"+externalGroup);
        defaultExternalMembers = list;
        assertEquals(previousSize+1, defaultExternalMembers.size());
        checkGetExternalGroups();
    }

    @Test
    public void testCreateExternalGroupMapUsingNameAlreadyExists() throws Exception {
        String displayName ="internal.read";
        String externalGroup = "cn=developers,ou=scopes,dc=test,dc=com";
        ResultActions result = createGroup(null, displayName, externalGroup);
        //we don't throw in JdbcScimGroupExternalMembershipManager.java
        //result.andExpect(status().isConflict());
        result.andExpect(status().isCreated());
    }

    @Test
    public void testCreateExternalGroupMapNameDoesNotExists() throws Exception {
        String displayName ="internal.read"+"sdasdas";
        String externalGroup = "cn=developers,ou=scopes,dc=test,dc=com";
        ResultActions result = createGroup(null, displayName, externalGroup);
        result.andExpect(status().isNotFound());
    }

    @Test
    public void testCreateExternalGroupMapNameIsNull() throws Exception {
        String externalGroup = "cn=developers,ou=scopes,dc=test,dc=com";
        ResultActions result = createGroup(null, null, externalGroup);
        result.andExpect(status().isNotFound());
    }

    @Test
    public void testCreateExternalGroupMapUsingId() throws Exception {
        String displayName ="internal.read";
        String groupId = getGroupId(displayName);
        String externalGroup = "cn=java-developers,ou=scopes,dc=test,dc=com";

        ResultActions result = createGroup(groupId, null, externalGroup);
        result.andExpect(status().isCreated());

        //add the newly added list to our expected list, and check again.
        int previousSize = defaultExternalMembers.size();
        ArrayList<String> list = new ArrayList<>(defaultExternalMembers);
        list.add(displayName+"|"+externalGroup);
        defaultExternalMembers = list;
        assertEquals(previousSize+1, defaultExternalMembers.size());
        checkGetExternalGroups();
    }

    @Test
    public void test_create_and_update_group_description() throws Exception {
        String name = new RandomValueStringGenerator().generate();
        ScimGroup group = new ScimGroup(name);
        group.setZoneId("some-other-zone");
        group.setDescription(name+"-description");

        String content = JsonUtils.writeValueAsString(group);
        MockHttpServletRequestBuilder action = MockMvcRequestBuilders.post("/Groups")
            .header("Authorization", "Bearer " + scimWriteToken)
            .contentType(MediaType.APPLICATION_JSON)
            .accept(APPLICATION_JSON)
            .content(content);

        ScimGroup newGroup =
            JsonUtils.readValue(
                getMockMvc().perform(action)
                    .andExpect(status().isCreated())
                    .andReturn().getResponse().getContentAsString(),
                ScimGroup.class
            );
        assertNotNull(newGroup);
        assertNotNull(newGroup.getId());
        assertEquals(IdentityZone.getUaa().getId(), newGroup.getZoneId());
        assertEquals(group.getDisplayName(), newGroup.getDisplayName());
        assertEquals(group.getDescription(), newGroup.getDescription());

        group.setDescription(name+"-description-updated");
        newGroup.setDescription(group.getDescription());

        content = JsonUtils.writeValueAsString(newGroup);
        action = MockMvcRequestBuilders.put("/Groups/"+newGroup.getId())
            .header("Authorization", "Bearer " + scimWriteToken)
            .header("If-Match", newGroup.getVersion())
            .contentType(MediaType.APPLICATION_JSON)
            .accept(APPLICATION_JSON)
            .content(content);

        newGroup =
            JsonUtils.readValue(
                getMockMvc().perform(action)
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString(),
                ScimGroup.class
            );

        assertNotNull(newGroup);
        assertNotNull(newGroup.getId());
        assertEquals(IdentityZone.getUaa().getId(), newGroup.getZoneId());
        assertEquals(group.getDisplayName(), newGroup.getDisplayName());
        assertEquals(group.getDescription(), newGroup.getDescription());

    }

    protected ResultActions createGroup(String id, String name, String externalName) throws Exception {
        ScimGroupExternalMember em = new ScimGroupExternalMember();
        if (id!=null) em.setGroupId(id);
        if (externalName!=null) em.setExternalGroup(externalName);
        if (name!=null) em.setDisplayName(name);
        String content = JsonUtils.writeValueAsString(em);
        MockHttpServletRequestBuilder post = MockMvcRequestBuilders.post("/Groups/External")
            .header("Authorization", "Bearer " + scimWriteToken)
            .contentType(MediaType.APPLICATION_JSON)
            .accept(APPLICATION_JSON)
            .content(content);

        ResultActions result = getMockMvc().perform(post);
        return result;
    }

    @Test
    public void testDeleteExternalGroupMapUsingNameDeprecatedAPI() throws Exception {
        String displayName ="internal.read";
        String externalGroup = "cn=developers,ou=scopes,dc=test,dc=com";
        ScimGroupExternalMember em = new ScimGroupExternalMember();
        em.setDisplayName(displayName);
        em.setExternalGroup(externalGroup);

        MockHttpServletRequestBuilder delete = MockMvcRequestBuilders.delete("/Groups/External/" + displayName + "/" + externalGroup)
            .header("Authorization", "Bearer " + scimWriteToken)
            .accept(APPLICATION_JSON);

        ResultActions result = getMockMvc().perform(delete);
        result.andExpect(status().isOk());

        //remove the deleted map from our expected list, and check again.
        int previousSize = defaultExternalMembers.size();
        ArrayList<String> list = new ArrayList<>(defaultExternalMembers);
        assertTrue(list.remove(displayName + "|" + externalGroup));
        defaultExternalMembers = list;
        assertEquals(previousSize-1, defaultExternalMembers.size());
        checkGetExternalGroups();
    }

    @Test
    public void testDeleteExternalGroupMapUsingName() throws Exception {
        String displayName ="internal.read";
        String externalGroup = "cn=developers,ou=scopes,dc=test,dc=com";
        ScimGroupExternalMember em = new ScimGroupExternalMember();
        em.setDisplayName(displayName);
        em.setExternalGroup(externalGroup);

        MockHttpServletRequestBuilder post = MockMvcRequestBuilders.delete("/Groups/External/displayName/" + displayName + "/externalGroup/" + externalGroup+"/origin/ldap")
            .header("Authorization", "Bearer " + scimWriteToken)
            .accept(APPLICATION_JSON);

        ResultActions result = getMockMvc().perform(post);
        result.andExpect(status().isOk());

        //remove the deleted map from our expected list, and check again.
        int previousSize = defaultExternalMembers.size();
        ArrayList<String> list = new ArrayList<>(defaultExternalMembers);
        assertTrue(list.remove(displayName + "|" + externalGroup));
        defaultExternalMembers = list;
        assertEquals(previousSize-1, defaultExternalMembers.size());
        checkGetExternalGroups();
    }

    @Test
    public void testDeleteExternalGroupMapUsingNonExistentName() throws Exception {
        String displayName ="internal.read.nonexistent";
        String externalGroup = "cn=developers,ou=scopes,dc=test,dc=com";
        ScimGroupExternalMember em = new ScimGroupExternalMember();
        em.setDisplayName(displayName);
        em.setExternalGroup(externalGroup);

        MockHttpServletRequestBuilder post = MockMvcRequestBuilders.delete("/Groups/External/displayName/" + displayName + "/externalGroup/" + externalGroup+"/origin/ldap")
            .header("Authorization", "Bearer " + scimWriteToken)
            .accept(APPLICATION_JSON);

        ResultActions result = getMockMvc().perform(post);
        result.andExpect(status().isNotFound());
    }

    @Test
    public void testDeleteExternalGroupMapUsingIdDeprecatedAPI() throws Exception {
        String displayName ="internal.read";
        String externalGroup = "cn=developers,ou=scopes,dc=test,dc=com";
        String groupId = getGroupId(displayName);

        MockHttpServletRequestBuilder post = MockMvcRequestBuilders.delete("/Groups/External/id/" + groupId + "/" + externalGroup)
            .header("Authorization", "Bearer " + scimWriteToken)
            .accept(APPLICATION_JSON);

        ResultActions result = getMockMvc().perform(post);
        result.andExpect(status().isOk());

        //remove the deleted map from our expected list, and check again.
        int previousSize = defaultExternalMembers.size();
        ArrayList<String> list = new ArrayList<>(defaultExternalMembers);
        assertTrue(list.remove(displayName + "|" + externalGroup));
        defaultExternalMembers = list;
        assertEquals(previousSize-1, defaultExternalMembers.size());
        checkGetExternalGroups();
    }

    @Test
    public void testDeleteExternalGroupMapUsingId() throws Exception {
        String displayName ="internal.read";
        String externalGroup = "cn=developers,ou=scopes,dc=test,dc=com";
        String origin = LDAP;
        String groupId = getGroupId(displayName);

        MockHttpServletRequestBuilder post = MockMvcRequestBuilders.delete("/Groups/External/groupId/" + groupId + "/externalGroup/" + externalGroup+"/origin/uaa")
            .header("Authorization", "Bearer " + scimWriteToken)
            .accept(APPLICATION_JSON);

        ResultActions result = getMockMvc().perform(post);
        result.andExpect(status().isNotFound());

        post = MockMvcRequestBuilders.delete("/Groups/External/groupId/" + groupId + "/externalGroup/" + externalGroup+"/origin/"+origin)
            .header("Authorization", "Bearer " + scimWriteToken)
            .accept(APPLICATION_JSON);

        result = getMockMvc().perform(post);
        result.andExpect(status().isOk());

        //remove the deleted map from our expected list, and check again.
        int previousSize = defaultExternalMembers.size();
        ArrayList<String> list = new ArrayList<>(defaultExternalMembers);
        assertTrue(list.remove(displayName + "|" + externalGroup));
        defaultExternalMembers = list;
        assertEquals(previousSize-1, defaultExternalMembers.size());
        checkGetExternalGroups();
    }

    @Test
    public void testDeleteExternalGroupMapUsingNonExistentId() throws Exception {
        String externalGroup = "cn=developers,ou=scopes,dc=test,dc=com";
        String groupId = "non-existent";

        MockHttpServletRequestBuilder post = MockMvcRequestBuilders.delete("/Groups/External/groupId/" + groupId + "/externalGroup/" + externalGroup+"/origin/ldap")
            .header("Authorization", "Bearer " + scimWriteToken)
            .accept(APPLICATION_JSON);

        ResultActions result = getMockMvc().perform(post);
        result.andExpect(status().isNotFound());
    }

    @Test
    public void testDeleteExternalGroupMapUsingReadToken() throws Exception {
        String displayName ="internal.read";
        String externalGroup = "cn=developers,ou=scopes,dc=test,dc=com";
        String groupId = getGroupId(displayName);

        MockHttpServletRequestBuilder post = MockMvcRequestBuilders.delete("/Groups/External/id/" + groupId + "/" + externalGroup+"/origin/ldap")
            .header("Authorization", "Bearer " + scimReadToken)
            .accept(APPLICATION_JSON);

        ResultActions result = getMockMvc().perform(post);
        result.andExpect(status().isForbidden());

        checkGetExternalGroups();
    }

    @Test
    public void testGetExternalGroupsFilter() throws Exception {
        checkGetExternalGroupsFilter("displayName", "internal.");
        checkGetExternalGroupsFilter("externalGroup", "o=springsource,o=org");
        checkGetExternalGroupsFilter("groupId", databaseExternalMembers.get(2).getGroupId());

    }

    @Test
    public void get_group_membership() throws Exception {
        String groupId = getGroupId("scim.read");
        MockHttpServletRequestBuilder get = get("/Groups/" + groupId + "/members/" + scimUser.getId())
                                                .header("Authorization", "Bearer " + scimReadToken);
        MvcResult mvcResult = getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andReturn();
        ScimGroupMember scimGroupMember = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), ScimGroupMember.class);
        assertNotNull(scimGroupMember);
        assertEquals(scimUser.getId(), scimGroupMember.getMemberId());
    }

    @Test
    public void get_group_membership_user_not_member_of_group() throws Exception {
        String groupId = getGroupId("scim.read");
        MockHttpServletRequestBuilder get = get("/Groups/" + groupId + "/members/id-of-random-user")
            .header("Authorization", "Bearer " + scimReadToken);
        getMockMvc().perform(get)
            .andExpect(status().isNotFound())
            .andReturn();
    }

    @Test
    public void get_group_membership_nonexistent_group() throws Exception {
        MockHttpServletRequestBuilder get = get("/Groups/nonexistent-group-id/members/" + scimUser.getId())
            .header("Authorization", "Bearer " + scimReadToken);
        getMockMvc().perform(get)
            .andExpect(status().isNotFound())
            .andReturn();
    }

    @Test
    public void get_group_membership_nonexistent_user() throws Exception {
        String groupId = getGroupId("scim.read");
        MockHttpServletRequestBuilder get = get("/Groups/" + groupId+ "/members/non-existent-user")
            .header("Authorization", "Bearer " + scimReadToken);
        getMockMvc().perform(get)
            .andExpect(status().isNotFound())
            .andReturn();
    }

    @Test
    public void get_all_group_memberships() throws Exception {
        String groupName = "random." + new RandomValueStringGenerator().generate();
        ScimGroup group = new ScimGroup(groupName);
        group = MockMvcUtils.createGroup(getMockMvc(), scimWriteToken, group);
        String groupId = getGroupId(groupName);
        assertEquals(group.getId(), groupId);

        scimUser = createUserAndAddToGroups(IdentityZone.getUaa(), new HashSet(Arrays.asList(groupName)));

        ScimUser secondUser = createUserAndAddToGroups(IdentityZone.getUaa(), Collections.singleton(groupName));
        ScimGroup innerGroup = createGroupWithinGroups(IdentityZone.getUaa(), Collections.singleton(groupName));

        MockHttpServletRequestBuilder get = get("/Groups/" + groupId + "/members/")
            .header("Authorization", "Bearer " + scimReadToken);
        MvcResult mvcResult = getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andReturn();
        String responseContent = mvcResult.getResponse().getContentAsString();
        List<Object> listMembers = JsonUtils.readValue(responseContent, new TypeReference<List<Object>>() {});
        Set<String> retrievedMembers = listMembers.stream().map(o -> JsonUtils.writeValueAsString(o)).collect(Collectors.toSet());

        Matcher<Iterable<? extends String>> containsExpectedMembers = containsInAnyOrder(
            JsonUtils.writeValueAsString(new ScimGroupMember(innerGroup.getId(), ScimGroupMember.Type.GROUP, Arrays.asList(ScimGroupMember.Role.MEMBER))),
            JsonUtils.writeValueAsString(new ScimGroupMember(secondUser.getId(), ScimGroupMember.Type.USER, Arrays.asList(ScimGroupMember.Role.MEMBER))),
            JsonUtils.writeValueAsString(new ScimGroupMember(scimUser.getId(), ScimGroupMember.Type.USER, Arrays.asList(ScimGroupMember.Role.MEMBER)))
        );

        Assert.assertThat(retrievedMembers, containsExpectedMembers);
    }

    @Test
    public void get_group_memberships_with_entities() throws Exception {

        String groupName = "random." + new RandomValueStringGenerator().generate();
        ScimGroup group = new ScimGroup(groupName);
        group = MockMvcUtils.createGroup(getMockMvc(), scimWriteToken, group);
        String groupId = getGroupId(groupName);
        assertEquals(group.getId(), groupId);

        scimUser = createUserAndAddToGroups(IdentityZone.getUaa(), new HashSet(Arrays.asList(groupName)));

        ScimUser secondUser = createUserAndAddToGroups(IdentityZone.getUaa(), Collections.singleton(groupName));
        ScimGroup innerGroup = createGroupWithinGroups(IdentityZone.getUaa(), Collections.singleton(groupName));

        MockHttpServletRequestBuilder get = get("/Groups/" + groupId + "/members/")
            .header("Authorization", "Bearer " + scimReadToken)
            .param("returnEntities", "true");
        MvcResult mvcResult = getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andReturn();
        String responseContent = mvcResult.getResponse().getContentAsString();
        List<Object> listMembers = JsonUtils.readValue(responseContent, new TypeReference<List<Object>>() {});
        Set<String> retrievedMembers = listMembers.stream().map(o -> JsonUtils.writeValueAsString(o)).collect(Collectors.toSet());

        Matcher<Iterable<? extends String>> containsExpectedMembers = containsInAnyOrder(
            JsonUtils.writeValueAsString(new ScimGroupMember(innerGroup)),
            JsonUtils.writeValueAsString(new ScimGroupMember(secondUser)),
            JsonUtils.writeValueAsString(new ScimGroupMember(scimUser))
        );

        Assert.assertThat(retrievedMembers, containsExpectedMembers);
    }

    @Test
    public void get_filtered_group_memberships() throws Exception {
        String groupName = "random." + new RandomValueStringGenerator().generate();
        ScimGroup group = new ScimGroup(groupName);
        group = MockMvcUtils.createGroup(getMockMvc(), scimWriteToken, group);
        String groupId = getGroupId(groupName);
        assertEquals(group.getId(), groupId);

        scimUser = createUserAndAddToGroups(IdentityZone.getUaa(), new HashSet(Arrays.asList(groupName)));

        ScimUser secondUser = createUserAndAddToGroups(IdentityZone.getUaa(), Collections.singleton(groupName));
        ScimGroup innerGroup = createGroupWithinGroups(IdentityZone.getUaa(), Collections.singleton(groupName));

        MockHttpServletRequestBuilder get = get("/Groups/" + groupId + "/members/")
            .header("Authorization", "Bearer " + scimReadToken)
            .param("filter", "member_type eq 'GROUP'");
        MvcResult mvcResult = getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andReturn();
        String responseContent = mvcResult.getResponse().getContentAsString();
        List<Object> listMembers = JsonUtils.readValue(responseContent, new TypeReference<List<Object>>() {});
        Set<String> retrievedMembers = listMembers.stream().map(o -> JsonUtils.writeValueAsString(o)).collect(Collectors.toSet());

        Matcher<Iterable<? extends String>> containsExpectedMembers = containsInAnyOrder(
            JsonUtils.writeValueAsString(new ScimGroupMember(innerGroup.getId(), ScimGroupMember.Type.GROUP, Arrays.asList(ScimGroupMember.Role.MEMBER)))
        );

        Assert.assertThat(retrievedMembers, containsExpectedMembers);
    }

    @Test
    public void get_group_memberships_for_nonexistent_group() throws Exception {
        MockHttpServletRequestBuilder get = get("/Groups/nonexistent-group-id/members/")
            .header("Authorization", "Bearer " + scimReadToken);
        getMockMvc().perform(get)
            .andExpect(status().isNotFound())
            .andReturn();
    }

    @Test
    public void add_member_to_group() throws Exception {
        ScimUser user = createUserAndAddToGroups(IdentityZone.getUaa(), Collections.EMPTY_SET);
        String groupId = getGroupId("scim.read");
        ScimGroupMember scimGroupMember = new ScimGroupMember(user.getId(), ScimGroupMember.Type.USER, Arrays.asList(ScimGroupMember.Role.MEMBER, ScimGroupMember.Role.READER));
        MockHttpServletRequestBuilder post = post("/Groups/" + groupId + "/members")
            .header("Authorization", "Bearer " + scimWriteToken)
            .header("Content-Type", APPLICATION_JSON_VALUE)
            .content(JsonUtils.writeValueAsString(scimGroupMember));
        String responseBody = getMockMvc().perform(post)
            .andExpect(status().isCreated())
            .andReturn().getResponse().getContentAsString();
        assertEquals(JsonUtils.writeValueAsString(scimGroupMember), responseBody);
    }

    @Test
    public void add_member_to_group_twice() throws Exception {
        ScimUser user = createUserAndAddToGroups(IdentityZone.getUaa(), Collections.EMPTY_SET);
        String groupId = getGroupId("scim.read");
        ScimGroupMember scimGroupMember = new ScimGroupMember(user.getId(), ScimGroupMember.Type.USER, Arrays.asList(ScimGroupMember.Role.MEMBER, ScimGroupMember.Role.READER));
        getMockMvc().perform(post("/Groups/" + groupId + "/members")
            .header("Authorization", "Bearer " + scimWriteToken)
            .header("Content-Type", APPLICATION_JSON_VALUE)
            .content(JsonUtils.writeValueAsString(scimGroupMember)))
            .andExpect(status().isCreated());

        scimGroupMember.setRoles(Arrays.asList(ScimGroupMember.Role.WRITER));
        getMockMvc().perform(post("/Groups/" + groupId + "/members")
            .header("Authorization", "Bearer " + scimWriteToken)
            .header("Content-Type", APPLICATION_JSON_VALUE)
            .content(JsonUtils.writeValueAsString(scimGroupMember)))
            .andExpect(status().isConflict());
    }

    @Test
    public void update_member_in_group() throws Exception {
        ScimUser user = createUserAndAddToGroups(IdentityZone.getUaa(), Collections.singleton("scim.read"));
        String groupId = getGroupId("scim.read");
        ScimGroupMember scimGroupMember = new ScimGroupMember(user.getId(), ScimGroupMember.Type.USER, Arrays.asList(ScimGroupMember.Role.MEMBER, ScimGroupMember.Role.READER));

        scimGroupMember.setRoles(Arrays.asList(ScimGroupMember.Role.WRITER));
        String updatedMember = JsonUtils.writeValueAsString(scimGroupMember);
        getMockMvc().perform(put("/Groups/" + groupId + "/members")
            .header("Authorization", "Bearer " + scimWriteToken)
            .header("Content-Type", APPLICATION_JSON_VALUE)
            .content(updatedMember))
            .andExpect(status().isOk());
        assertNotNull(updatedMember);

        MockHttpServletRequestBuilder get = get("/Groups/" + groupId + "/members/" + scimGroupMember.getMemberId())
            .header("Authorization", "Bearer " + scimReadToken);
        MvcResult mvcResult = getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andReturn();
        String getResponse = mvcResult.getResponse().getContentAsString();
        assertEquals(updatedMember, getResponse);
    }

    @Test
    public void update_member_in_nonexistent_group() throws Exception {
        ScimGroupMember scimGroupMember = new ScimGroupMember(scimUser.getId(), ScimGroupMember.Type.USER, Arrays.asList(ScimGroupMember.Role.MEMBER, ScimGroupMember.Role.READER));

        getMockMvc().perform(put("/Groups/nonexistent-group-id/members")
            .header("Authorization", "Bearer " + scimWriteToken)
            .header("Content-Type", APPLICATION_JSON_VALUE)
            .content(JsonUtils.writeValueAsString(scimGroupMember)))
            .andExpect(status().isNotFound());
    }

    @Test
    public void update_member_does_not_exist_in_group() throws Exception {
        ScimGroupMember scimGroupMember = new ScimGroupMember(scimUser.getId(), ScimGroupMember.Type.USER, Arrays.asList(ScimGroupMember.Role.MEMBER, ScimGroupMember.Role.READER));

        String groupId = getGroupId("acme");
        getMockMvc().perform(put("/Groups/" + groupId + "/members")
            .header("Authorization", "Bearer " + scimWriteToken)
            .header("Content-Type", APPLICATION_JSON_VALUE)
            .content(JsonUtils.writeValueAsString(scimGroupMember)))
            .andExpect(status().isNotFound());
    }

    @Test
    public void update_nonexistent_user() throws Exception {
        ScimGroupMember scimGroupMember = new ScimGroupMember("non-existent-user", ScimGroupMember.Type.USER, Arrays.asList(ScimGroupMember.Role.MEMBER, ScimGroupMember.Role.READER));

        String groupId = getGroupId("scim.read");
        getMockMvc().perform(put("/Groups/" + groupId + "/members")
            .header("Authorization", "Bearer " + scimWriteToken)
            .header("Content-Type", APPLICATION_JSON_VALUE)
            .content(JsonUtils.writeValueAsString(scimGroupMember)))
            .andExpect(status().isNotFound());
    }

    @Test
    public void delete_member_from_group() throws Exception {
        ScimUser user = createUserAndAddToGroups(IdentityZone.getUaa(), Collections.singleton("scim.read"));
        String groupId = getGroupId("scim.read");

        String deleteResponseBody = getMockMvc().perform(delete("/Groups/" + groupId + "/members/" + user.getId())
            .header("Authorization", "Bearer " + scimWriteToken)
            .header("Content-Type", APPLICATION_JSON_VALUE))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

        ScimGroupMember deletedMember = JsonUtils.readValue(deleteResponseBody, ScimGroupMember.class);

        assertEquals(user.getId(), deletedMember.getMemberId());
    }

    @Test
    public void delete_member_from_nonexistent_group() throws Exception {
        ScimUser user = createUserAndAddToGroups(IdentityZone.getUaa(), Collections.singleton("scim.read"));

        getMockMvc().perform(delete("/Groups/nonexistent-group/members/" + user.getId())
            .header("Authorization", "Bearer " + scimWriteToken)
            .header("Content-Type", APPLICATION_JSON_VALUE))
            .andExpect(status().isNotFound());
    }

    @Test
    public void delete_user_not_member_of_group() throws Exception {
        String groupId = getGroupId("acme");
        getMockMvc().perform(delete("/Groups/" + groupId + "/members/" + scimUser.getId())
            .header("Authorization", "Bearer " + scimWriteToken)
            .header("Content-Type", APPLICATION_JSON_VALUE))
            .andExpect(status().isNotFound());
    }

    @Test
    public void delete_nonexistent_user() throws Exception {
        getMockMvc().perform(delete("/Groups/nonexistent-group/members/non-existent-user")
            .header("Authorization", "Bearer " + scimWriteToken)
            .header("Content-Type", APPLICATION_JSON_VALUE))
            .andExpect(status().isNotFound());
    }

    @Test
    public void patch_has_one_path() throws Exception {
        getMockMvc().perform(
            patch("/Group/groupId/members")
                .header("Authorization", "Bearer " + scimWriteToken)
                .header("Content-Type", APPLICATION_JSON_VALUE)
        )
            .andDo(print())
            .andExpect(status().isFound()) //gets caught by the ui filter for unknown URIs
            .andExpect(redirectedUrl("http://localhost/login"));
    }

    @Test
    public void add_member_bad_token() throws Exception {
        ScimUser user = createUserAndAddToGroups(IdentityZone.getUaa(), Collections.EMPTY_SET);
        String groupId = getGroupId("scim.read");
        String anyOldToken = testClient.getClientCredentialsOAuthAccessToken(clientId, clientSecret,"other.scope");

        ScimGroupMember scimGroupMember = new ScimGroupMember(user.getId(), ScimGroupMember.Type.USER, Arrays.asList(ScimGroupMember.Role.MEMBER, ScimGroupMember.Role.READER));

        MockHttpServletRequestBuilder post = post("/Groups/" + groupId + "/members")
            .header("Authorization", "Bearer " + anyOldToken)
            .header("Content-Type", APPLICATION_JSON_VALUE)
            .content(JsonUtils.writeValueAsString(scimGroupMember));
        getMockMvc().perform(post)
            .andExpect(status().isForbidden());

    }

    @Test
    public void add_member_to_nonexistent_group() throws Exception {
        ScimUser user = createUserAndAddToGroups(IdentityZone.getUaa(), Collections.EMPTY_SET);
        ScimGroupMember scimGroupMember = new ScimGroupMember(user.getId(), ScimGroupMember.Type.USER, Arrays.asList(ScimGroupMember.Role.MEMBER, ScimGroupMember.Role.READER));
        MockHttpServletRequestBuilder post = post("/Groups/nonexistent-group-id/members")
            .header("Authorization", "Bearer " + scimWriteToken)
            .header("Content-Type", APPLICATION_JSON_VALUE)
            .content(JsonUtils.writeValueAsString(scimGroupMember));
        getMockMvc().perform(post)
            .andExpect(status().isNotFound());
    }

    @Test
    public void add_nonexistent_user_to_group() throws Exception {
        String groupId = getGroupId("scim.read");
        ScimGroupMember scimGroupMember = new ScimGroupMember("random-user-id", ScimGroupMember.Type.USER, Arrays.asList(ScimGroupMember.Role.MEMBER, ScimGroupMember.Role.READER));
        MockHttpServletRequestBuilder post = post("/Groups/" + groupId + "/members")
            .header("Authorization", "Bearer " + scimWriteToken)
            .header("Content-Type", APPLICATION_JSON_VALUE)
            .content(JsonUtils.writeValueAsString(scimGroupMember));
        getMockMvc().perform(post)
            .andExpect(status().isNotFound());
    }

    protected void checkGetExternalGroupsFilter(String fieldName, String fieldValue) throws Exception {
        MockHttpServletRequestBuilder get = get("/Groups/External")
            .param("filter", fieldName+" co \""+fieldValue+"\"")
            .header("Authorization", "Bearer " + scimReadToken)
            .accept(APPLICATION_JSON);

        ResultActions result = getMockMvc().perform(get);
        result.andExpect(status().isOk());
        String content = result.andReturn().getResponse().getContentAsString();
        SearchResults<ScimGroupExternalMember> members;

        Map<String,Object> map = JsonUtils.readValue(content, Map.class);
        List<Map<String,String>> resources = (List<Map<String,String>>)map.get("resources");
        int startIndex = Integer.parseInt(map.get("startIndex").toString());
        int itemsPerPage = Integer.parseInt(map.get("itemsPerPage").toString());
        int totalResults = Integer.parseInt(map.get("totalResults").toString());
        List<ScimGroupExternalMember> memberList = new ArrayList<>();
        for (Map<String,String> m : resources) {
            ScimGroupExternalMember sgm = new ScimGroupExternalMember();
            sgm.setGroupId(m.get("groupId"));
            sgm.setDisplayName(m.get("displayName"));
            sgm.setExternalGroup(m.get("externalGroup"));
            sgm.setOrigin(m.get("origin"));
            memberList.add(sgm);
        }
        members = new SearchResults<>((List<String>)map.get("schemas"), memberList, startIndex, itemsPerPage, totalResults);
        assertNotNull(members);

        List<ScimGroupExternalMember> expected = new ArrayList<>();
        for (ScimGroupExternalMember m : databaseExternalMembers) {
            switch (fieldName) {
                case "displayName" : {
                    if (m.getDisplayName().startsWith(fieldValue)) {
                        expected.add(m);
                    }
                    break;
                }
                case "externalGroup" : {
                    if (m.getExternalGroup().contains(fieldValue)) {
                        expected.add(m);
                    }
                    break;
                }
                case "groupId" : {
                    if (m.getGroupId().contains(fieldValue)) {
                        expected.add(m);
                    }
                    break;
                }
            }
        }

        assertEquals(expected.size(), members.getResources().size());
        validateDbMembers(expected, members.getResources());
    }

    @Test
    public void testGetExternalGroupsPagination() throws Exception {
        checkGetExternalGroupsPagination(1);
        checkGetExternalGroupsPagination(2);
        checkGetExternalGroupsPagination(3);
        checkGetExternalGroupsPagination(4);
        checkGetExternalGroupsPagination(5);
        checkGetExternalGroupsPagination(6);
        checkGetExternalGroupsPagination(100);
    }


    protected void checkGetExternalGroupsPagination(int pageSize) throws Exception {
        List<SearchResults<ScimGroupExternalMember>> pages = new ArrayList<>();

        for(int start = 1; start <= databaseExternalMembers.size(); start += pageSize)
        {
            MockHttpServletRequestBuilder get = get("/Groups/External")
            .param("startIndex",String.valueOf(start))
            .param("count", String.valueOf(pageSize))
            .header("Authorization", "Bearer " + scimReadToken)
            .accept(APPLICATION_JSON);

            ResultActions result = getMockMvc().perform(get);
            result.andExpect(status().isOk());
            String content = result.andReturn().getResponse().getContentAsString();
            SearchResults<ScimGroupExternalMember> page = null;

            Map<String,Object> map = JsonUtils.readValue(content, Map.class);
            List<Map<String,String>> resources = (List<Map<String,String>>)map.get("resources");
            int startIndex = Integer.parseInt(map.get("startIndex").toString());
            int itemsPerPage = Integer.parseInt(map.get("itemsPerPage").toString());
            int totalResults = Integer.parseInt(map.get("totalResults").toString());
            List<ScimGroupExternalMember> memberList = new ArrayList<>();
            for (Map<String,String> m : resources) {
                ScimGroupExternalMember sgm = new ScimGroupExternalMember();
                sgm.setGroupId(m.get("groupId"));
                sgm.setDisplayName(m.get("displayName"));
                sgm.setExternalGroup(m.get("externalGroup"));
                sgm.setOrigin(m.get("origin"));
                memberList.add(sgm);
            }
            page = new SearchResults<>((List<String>)map.get("schemas"), memberList, startIndex, itemsPerPage, totalResults);
            pages.add(page);
        }

        List<ScimGroupExternalMember> members = pages.stream().flatMap(p -> p.getResources().stream()).collect(Collectors.toList());

        validateDbMembers(databaseExternalMembers, members);
    }

    protected void checkGetExternalGroups() throws Exception {
        String path = "/Groups/External";
        checkGetExternalGroups(path);
        path = "/Groups/External";
        checkGetExternalGroups(path);
    }
    protected void checkGetExternalGroups(String path) throws Exception {
        MockHttpServletRequestBuilder get = get(path)
            .header("Authorization", "Bearer " + scimReadToken)
            .accept(APPLICATION_JSON);

        ResultActions result = getMockMvc().perform(get);
        result.andExpect(status().isOk());
        String content = result.andReturn().getResponse().getContentAsString();
        SearchResults<ScimGroupExternalMember> members = null;

        Map<String,Object> map = JsonUtils.readValue(content, Map.class);
        List<Map<String,String>> resources = (List<Map<String,String>>)map.get("resources");
        int startIndex = Integer.parseInt(map.get("startIndex").toString());
        int itemsPerPage = Integer.parseInt(map.get("itemsPerPage").toString());
        int totalResults = Integer.parseInt(map.get("totalResults").toString());
        List<ScimGroupExternalMember> memberList = new ArrayList<>();
        for (Map<String,String> m : resources) {
            ScimGroupExternalMember sgm = new ScimGroupExternalMember();
            sgm.setGroupId(m.get("groupId"));
            sgm.setDisplayName(m.get("displayName"));
            sgm.setExternalGroup(m.get("externalGroup"));
            sgm.setOrigin(m.get("origin"));
            memberList.add(sgm);
        }
        members = new SearchResults<>((List<String>)map.get("schemas"), memberList, startIndex, itemsPerPage, totalResults);
        assertNotNull(members);
        assertEquals(defaultExternalMembers.size(), members.getResources().size());
        validateMembers(defaultExternalMembers, members.getResources());
    }

    protected String getGroupId(String displayName) throws Exception {
        JdbcScimGroupProvisioning gp = (JdbcScimGroupProvisioning) getWebApplicationContext().getBean("scimGroupProvisioning");
        List<ScimGroup> result = gp.query("displayName eq \""+displayName+"\"");
        if (result==null || result.size()==0) {
            throw new NullPointerException("Group not found:"+displayName);
        }
        if (result.size()>1) {
            throw new IllegalStateException("Group name should be unique:"+displayName);
        }
        return result.get(0).getId();
    }

    protected void validateMembers(List<String> expected, Collection<ScimGroupExternalMember> actual) {
        List<ScimGroupExternalMember> members = new ArrayList<>();
        for (String s : expected) {
            String[] data = s.split("\\|");
            assertNotNull(data);
            assertEquals(2, data.length);
            String displayName = data[0];
            String externalId = data[1];
            ScimGroupExternalMember mbr = new ScimGroupExternalMember("N/A", externalId);
            mbr.setDisplayName(displayName);
            mbr.setOrigin(OriginKeys.LDAP);
            members.add(mbr);
        }
        validateDbMembers(members, actual);
    }
    protected void validateDbMembers(Collection<ScimGroupExternalMember> expected, Collection<ScimGroupExternalMember> actual) {
        for (ScimGroupExternalMember s : expected) {
            final String displayName = s.getDisplayName();
            final String externalId = s.getExternalGroup();
            final String origin = s.getOrigin();
            boolean found = false;
            for (ScimGroupExternalMember m : actual) {
                assertNotNull("Display name can not be null", m.getDisplayName());
                assertNotNull("External ID can not be null", m.getExternalGroup());
                if (m.getDisplayName().equals(displayName) && m.getExternalGroup().equals(externalId) && m.getOrigin().equals(origin)) {
                    found = true;
                    break;
                }
            }
            assertTrue("Did not find expected external group mapping:"+s,found);
            assertEquals("The result set must contain exactly as many items as expected", expected.size(), actual.size());
        }
    }

    private ScimUser createUserAndAddToGroups(IdentityZone zone, Set<String> groupNames) throws Exception {
        if (zone == null) {
            zone = IdentityZone.getUaa();
        }
        ScimUserProvisioning usersRepository = getWebApplicationContext().getBean(ScimUserProvisioning.class);
        ScimGroupProvisioning groupRepository = getWebApplicationContext().getBean(ScimGroupProvisioning.class);
        String email = "otheruser@"+generator.generate().toLowerCase()+".com";
        ScimUser user = new ScimUser(null, email, "Other", "User");
        user.addEmail(email);
        user.setVerified(true);
        IdentityZone originalZone = IdentityZoneHolder.get();
        try {
            if (zone != null) {
                IdentityZoneHolder.set(zone);
            }
            user.setOrigin(OriginKeys.UAA);
            user = usersRepository.createUser(user, "password");
            ephemeralResources.add(new String[] {user.getId(), "USER"});

            Collection<ScimUser.Group> scimUserGroups = new LinkedList<>();
            for (String groupName : groupNames) {
                List<ScimGroup> scimGroups = groupRepository.query("displayName eq \""+ groupName +"\"");
                ScimUser.Group scimUserGroup;
                ScimGroup group;
                if (scimGroups==null || scimGroups.isEmpty()) {
                    group = new ScimGroup(null, groupName,IdentityZoneHolder.get().getId());
                    group = groupRepository.create(group);
                    scimUserGroup = new ScimUser.Group(group.getId(), groupName);
                } else {
                    group = scimGroups.get(0);
                    scimUserGroup = new ScimUser.Group(scimGroups.get(0).getId(), groupName);
                }
                scimUserGroups.add(scimUserGroup);
                ScimGroupMembershipManager scimGroupMembershipManager = getWebApplicationContext().getBean(ScimGroupMembershipManager.class);
                ScimGroupMember member = new ScimGroupMember(user.getId(), ScimGroupMember.Type.USER, Arrays.asList(ScimGroupMember.Role.READER));
                try {
                    scimGroupMembershipManager.addMember(group.getId(), member);
                } catch (MemberAlreadyExistsException x) {}
            }
        } finally {
            IdentityZoneHolder.set(originalZone);
        }
        return user;
    }

    private ScimGroup createGroupWithinGroups(IdentityZone zone, Set<String> groupNames) throws Exception {
        if (zone == null) {
            zone = IdentityZone.getUaa();
        }
        ScimGroupProvisioning groupRepository = getWebApplicationContext().getBean(ScimGroupProvisioning.class);
        ScimGroup newGroup = new ScimGroup(null, generator.generate(), zone.getId());
        IdentityZone originalZone = IdentityZoneHolder.get();
        try {
            if (zone != null) {
                IdentityZoneHolder.set(zone);
            }
            newGroup = groupRepository.create(newGroup);
            ephemeralResources.add(new String[] {newGroup.getId(), "GROUP"});

            Collection<ScimUser.Group> scimUserGroups = new LinkedList<>();
            for (String groupName : groupNames) {
                List<ScimGroup> scimGroups = groupRepository.query("displayName eq \""+ groupName +"\"");
                ScimUser.Group scimUserGroup;
                ScimGroup group;
                if (scimGroups==null || scimGroups.isEmpty()) {
                    group = new ScimGroup(null, groupName,IdentityZoneHolder.get().getId());
                    group = groupRepository.create(group);
                    scimUserGroup = new ScimUser.Group(group.getId(), groupName);
                } else {
                    group = scimGroups.get(0);
                    scimUserGroup = new ScimUser.Group(scimGroups.get(0).getId(), groupName);
                }
                scimUserGroups.add(scimUserGroup);
                ScimGroupMembershipManager scimGroupMembershipManager = getWebApplicationContext().getBean(ScimGroupMembershipManager.class);
                ScimGroupMember member = new ScimGroupMember(newGroup.getId(), ScimGroupMember.Type.GROUP, Arrays.asList(ScimGroupMember.Role.READER));
                try {
                    scimGroupMembershipManager.addMember(group.getId(), member);
                } catch (MemberAlreadyExistsException x) {}
            }
        } finally {
            IdentityZoneHolder.set(originalZone);
        }
        return newGroup;
    }

}
