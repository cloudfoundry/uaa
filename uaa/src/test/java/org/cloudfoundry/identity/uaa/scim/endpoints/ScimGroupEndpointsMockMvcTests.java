package org.cloudfoundry.identity.uaa.scim.endpoints;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.Sets;
import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.OAuthToken;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
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
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.UserConfig;
import org.cloudfoundry.identity.uaa.zone.ZoneManagementScopes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.util.StringUtils.hasText;

@DefaultTestContext
class ScimGroupEndpointsMockMvcTests {

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

    private WebApplicationContext webApplicationContext;
    private MockMvc mockMvc;
    private TestClient testClient;

    @BeforeEach
    void setUp(
            @Autowired WebApplicationContext webApplicationContext,
            @Autowired TestClient testClient,
            @Autowired MockMvc mockMvc) throws Exception {
        this.webApplicationContext = webApplicationContext;
        this.mockMvc = mockMvc;
        this.testClient = testClient;

        if (originalDatabaseExternalMembers == null) {
            originalDatabaseExternalMembers = this.webApplicationContext.getBean(JdbcScimGroupExternalMembershipManager.class).getExternalGroupMappings(IdentityZoneHolder.get().getId());
            originalDefaultExternalMembers = originalDatabaseExternalMembers.stream().map(m -> (m.getDisplayName() + "|" + m.getExternalGroup())).toList();
        }

        if (bootstrap == null) {
            bootstrap = this.webApplicationContext.getBean(ScimExternalGroupBootstrap.class);
        }

        if (template == null) {
            template = this.webApplicationContext.getBean(JdbcTemplate.class);
        }

        template.update("delete from external_group_mapping");
        bootstrap.afterPropertiesSet();

        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret",
                "clients.read clients.write clients.secret clients.admin");
        clientId = generator.generate().toLowerCase();
        clientSecret = generator.generate().toLowerCase();
        String authorities = "scim.read,scim.write,password.write,oauth.approvals,scim.create,other.scope";
        MockMvcUtils.createClient(mockMvc, adminToken, clientId, clientSecret, Collections.singleton("oauth"), Arrays.asList("foo", "bar", "scim.read"), Arrays.asList("client_credentials", "password"), authorities);
        scimReadToken = testClient.getClientCredentialsOAuthAccessToken(clientId, clientSecret, "scim.read password.write");
        scimWriteToken = testClient.getClientCredentialsOAuthAccessToken(clientId, clientSecret, "scim.write password.write");

        defaultExternalMembers = new LinkedList<>(originalDefaultExternalMembers);
        databaseExternalMembers = new LinkedList<>(
                this.webApplicationContext.getBean(JdbcScimGroupExternalMembershipManager.class).getExternalGroupMappings(IdentityZoneHolder.get().getId())
        );

        scimUser = createUserAndAddToGroups(IdentityZone.getUaa(), Sets.newHashSet(Arrays.asList("scim.read", "scim.write", "scim.me")));
        scimReadUserToken = testClient.getUserOAuthAccessToken("cf", "", scimUser.getUserName(), "password", "scim.read");
        identityClientToken = testClient.getClientCredentialsOAuthAccessToken("identity", "identitysecret", "");
    }

    @AfterEach
    void cleanUp() {
        for (Object[] resource : ephemeralResources) {
            template.update("delete from group_membership where member_id = ? and member_type = ?", resource);
        }
        ephemeralResources.clear();
    }

    @Test
    void identityClientManagesZoneAdmins() throws Exception {
        IdentityZone zone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityClientToken);
        ScimGroupMember member = new ScimGroupMember(scimUser.getId());
        ScimGroup group = new ScimGroup(null, "zones." + zone.getId() + ".admin", zone.getId());
        group.setMembers(Collections.singletonList(member));
        MockHttpServletRequestBuilder post = post("/Groups/zones")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .header("Authorization", "Bearer " + identityClientToken)
                .content(JsonUtils.writeValueAsBytes(group));
        //create the zones.{id}.admin
        mockMvc.perform(post)
                .andExpect(status().isCreated());

        MockHttpServletRequestBuilder delete = delete("/Groups/zones/{userId}/{zoneId}", scimUser.getId(), zone.getId())
                .header("Authorization", "Bearer " + identityClientToken);
        //delete the zones.{id}.admin
        mockMvc.perform(delete).andExpect(status().isOk());
        //the relationship is not found
        mockMvc.perform(delete).andExpect(status().isNotFound());

        //try a regular scim token
        mockMvc.perform(post("/Groups/zones")
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_JSON)
                        .header("Authorization", "Bearer " + scimWriteToken)
                        .content(JsonUtils.writeValueAsBytes(group)))
                .andExpect(status().isForbidden());

        mockMvc.perform(delete("/Groups/zones/{userId}/{zoneId}", scimUser.getId(), zone.getId())
                        .header("Authorization", "Bearer " + scimWriteToken))
                .andExpect(status().isForbidden());

        mockMvc.perform(delete("/Groups/zones/{userId}/{zoneId}", "nonexistent", zone.getId())
                        .header("Authorization", "Bearer " + identityClientToken))
                .andExpect(status().isNotFound());

        mockMvc.perform(post("/Groups/zones")
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_JSON)
                        .header("Authorization", "Bearer " + identityClientToken)
                        .content(""))
                .andExpect(status().isBadRequest());

        //add two users to the same zone
        for (int i = 0; i < 2; i++) {
            ScimUser user = createUserAndAddToGroups(IdentityZone.getUaa(), Sets.newHashSet(Arrays.asList("scim.read", "scim.write", "scim.me")));
            member = new ScimGroupMember(user.getId());
            group = new ScimGroup(null, "zones." + zone.getId() + ".admin", zone.getId());
            group.setMembers(Collections.singletonList(member));

            post = post("/Groups/zones")
                    .accept(APPLICATION_JSON)
                    .contentType(APPLICATION_JSON)
                    .header("Authorization", "Bearer " + identityClientToken)
                    .content(JsonUtils.writeValueAsBytes(group));
            //create the zones.{id}.admin
            mockMvc.perform(post)
                    .andExpect(status().isCreated());
        }
    }

    @Test
    void limitedScopesWithoutMember() throws Exception {
        IdentityZone zone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityClientToken);
        ScimGroup group = new ScimGroup("zones." + zone.getId() + ".admin");

        MockHttpServletRequestBuilder post = post("/Groups/zones")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .header("Authorization", "Bearer " + identityClientToken)
                .content(JsonUtils.writeValueAsBytes(group));

        mockMvc.perform(post)
                .andExpect(status().isBadRequest());
    }

    @Test
    void add_and_Delete_Members_toZoneManagementGroups_withVariousGroupNames() throws Exception {
        addAndDeleteMembersToZoneManagementGroups("zones.%s.admin", HttpStatus.CREATED, HttpStatus.OK);
        addAndDeleteMembersToZoneManagementGroups("zones.%s.read", HttpStatus.CREATED, HttpStatus.OK);
        addAndDeleteMembersToZoneManagementGroups("zones.%s.clients.read", HttpStatus.CREATED, HttpStatus.OK);
        addAndDeleteMembersToZoneManagementGroups("zones.%s.clients.write", HttpStatus.CREATED, HttpStatus.OK);
        addAndDeleteMembersToZoneManagementGroups("zones.%s.clients.admin", HttpStatus.CREATED, HttpStatus.OK);
        addAndDeleteMembersToZoneManagementGroups("zones.%s.idps.read", HttpStatus.CREATED, HttpStatus.OK);

        addAndDeleteMembersToZoneManagementGroups("zones.%s.blah.clients.read", HttpStatus.BAD_REQUEST, null);
        addAndDeleteMembersToZoneManagementGroups("zones.%s.invalid", HttpStatus.BAD_REQUEST, null);

        addAndDeleteMembersToZoneManagementGroups("zones..admin", HttpStatus.BAD_REQUEST, null);
    }

    private void addAndDeleteMembersToZoneManagementGroups(String displayName, HttpStatus create, HttpStatus delete) throws Exception {
        IdentityZone zone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityClientToken);
        ScimGroupMember member = new ScimGroupMember(scimUser.getId());
        ScimGroup group = new ScimGroup(displayName.formatted(zone.getId()));
        group.setMembers(Collections.singletonList(member));

        createZoneScope(group).andExpect(status().is(create.value()));

        if (delete != null) {
            deleteZoneScope(zone, group).andExpect(status().is(delete.value()));
        }
    }

    private ResultActions deleteZoneScope(IdentityZone zone, ScimGroup group) throws Exception {
        String removeS = "zones.%s.".formatted(zone.getId());
        String scope = group.getDisplayName().substring(removeS.length());
        MockHttpServletRequestBuilder delete = delete("/Groups/zones/{userId}/{zoneId}/{scope}", scimUser.getId(), zone.getId(), scope)
                .accept(APPLICATION_JSON)
                .header("Authorization", "Bearer " + identityClientToken);
        return mockMvc.perform(delete);
    }

    private ResultActions createZoneScope(ScimGroup group) throws Exception {
        MockHttpServletRequestBuilder post = post("/Groups/zones")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .header("Authorization", "Bearer " + identityClientToken)
                .content(JsonUtils.writeValueAsBytes(group));
        return mockMvc.perform(post);
    }

    @Test
    void groupOperationsAsZoneAdmin() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        String zoneAdminToken = result.getZoneAdminToken();
        IdentityZone zone = result.getIdentityZone();

        String groupName = generator.generate();
        String headerName = IdentityZoneSwitchingFilter.HEADER;
        String headerValue = zone.getId();

        ScimGroup group = new ScimGroup(null, groupName, null);

        MockHttpServletRequestBuilder create = post("/Groups")
                .header(headerName, headerValue)
                .header("Authorization", "bearer " + zoneAdminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(group));

        group = JsonUtils.readValue(
                mockMvc.perform(create)
                        .andExpect(status().isCreated())
                        .andReturn().getResponse().getContentAsString(),
                ScimGroup.class);

        MockHttpServletRequestBuilder update = put("/Groups/" + group.getId())
                .header(headerName, headerValue)
                .header("Authorization", "bearer " + zoneAdminToken)
                .header("If-Match", group.getVersion())
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(group));

        group = JsonUtils.readValue(
                mockMvc.perform(update)
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString(),
                ScimGroup.class);

        MockHttpServletRequestBuilder get = get("/Groups/" + group.getId())
                .header(headerName, headerValue)
                .header("Authorization", "bearer " + zoneAdminToken)
                .accept(APPLICATION_JSON);

        assertThat(JsonUtils.readValue(
                mockMvc.perform(get)
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString(),
                ScimGroup.class)).isEqualTo(group);
    }

    @Test
    void getGroups_withScimReadTokens_returnsOkWithResults() throws Exception {
        String filterNarrow = "displayName eq \"clients.read\" or displayName eq \"clients.write\"";
        String filterWide = "displayName eq \"clients.read\" or displayName eq \"clients.write\" or displayName eq \"zones.read\" or displayName eq \"zones.write\"";

        MockHttpServletRequestBuilder get = get("/Groups")
                .header("Authorization", "Bearer " + scimReadToken)
                .param("attributes", "displayName")
                .param("filter", filterNarrow)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(APPLICATION_JSON);
        MvcResult mvcResult = mockMvc.perform(get)
                .andExpect(status().isOk())
                .andReturn();

        String body = mvcResult.getResponse().getContentAsString();
        SearchResults<ScimGroup> searchResults = JsonUtils.readValue(body, SearchResults.class);
        assertThat(searchResults.getResources()).as("Search results: " + body).hasSize(2);

        get = get("/Groups")
                .header("Authorization", "Bearer " + scimReadUserToken)
                .param("attributes", "displayName")
                .param("filter", filterNarrow)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(APPLICATION_JSON);
        mvcResult = mockMvc.perform(get)
                .andExpect(status().isOk())
                .andReturn();

        body = mvcResult.getResponse().getContentAsString();
        searchResults = JsonUtils.readValue(body, SearchResults.class);
        assertThat(searchResults.getResources()).as("Search results: " + body).hasSize(2);

        get = get("/Groups")
                .header("Authorization", "Bearer " + scimReadToken)
                .contentType(MediaType.APPLICATION_JSON)
                .param("filter", filterWide)
                .accept(APPLICATION_JSON);
        mvcResult = mockMvc.perform(get)
                .andExpect(status().isOk())
                .andReturn();

        body = mvcResult.getResponse().getContentAsString();
        searchResults = JsonUtils.readValue(body, SearchResults.class);
        assertThat(searchResults.getResources()).as("Search results: " + body).hasSize(4);

        get = get("/Groups")
                .header("Authorization", "Bearer " + scimReadUserToken)
                .contentType(MediaType.APPLICATION_JSON)
                .param("filter", filterWide)
                .accept(APPLICATION_JSON);
        mvcResult = mockMvc.perform(get)
                .andExpect(status().isOk())
                .andReturn();

        body = mvcResult.getResponse().getContentAsString();
        searchResults = JsonUtils.readValue(body, SearchResults.class);
        assertThat(searchResults.getResources()).as("Search results: " + body).hasSize(4);
    }

    @Nested
    @DefaultTestContext
    @TestPropertySource(properties = {
            "groupMaxCount=50"
    })
    class WithGroupMaxCount50 {

        @Autowired
        private MockMvc mockMvc;

        @Autowired
        private WebApplicationContext webApplicationContext;

        @Test
        void getGroupsInOtherZone_withZoneAdminToken_returnsOkWithResults() throws Exception {
            String subdomain = new RandomValueStringGenerator(8).generate();
            UaaClientDetails bootstrapClient = null;
            MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(
                    subdomain, mockMvc, webApplicationContext, bootstrapClient, IdentityZoneHolder.getCurrentZoneId()
            );

            ScimGroup group1 = new ScimGroup(null, "scim.whatever", result.getIdentityZone().getId());
            ScimGroup group2 = new ScimGroup(null, "another.group", result.getIdentityZone().getId());

            mockMvc.perform(post("/Groups")
                            .header(IdentityZoneSwitchingFilter.HEADER, result.getIdentityZone().getId())
                            .header("Authorization", "bearer " + result.getZoneAdminToken())
                            .accept(APPLICATION_JSON)
                            .contentType(APPLICATION_JSON)
                            .content(JsonUtils.writeValueAsString(group1)))
                    .andExpect(status().isCreated());

            mockMvc.perform(post("/Groups")
                            .header(IdentityZoneSwitchingFilter.HEADER, result.getIdentityZone().getId())
                            .header("Authorization", "bearer " + result.getZoneAdminToken())
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
            MvcResult mvcResult = mockMvc.perform(get)
                    .andExpect(status().isOk())
                    .andReturn();

            SearchResults searchResults = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), SearchResults.class);
            assertThat(getSystemScopes("scim").size() + 1).isEqualTo(searchResults.getResources().size());

            get = get("/Groups")
                    .header("Authorization", "Bearer " + result.getZoneAdminToken())
                    .header(IdentityZoneSwitchingFilter.HEADER, result.getIdentityZone().getId())
                    .contentType(MediaType.APPLICATION_JSON)
                    .accept(APPLICATION_JSON);
            mvcResult = mockMvc.perform(get)
                    .andExpect(status().isOk())
                    .andReturn();

            searchResults = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), SearchResults.class);
            assertThat(UserConfig.DEFAULT_ZONE_GROUPS.size() +
                    getSystemScopes(null).size() + 2 - 1).isEqualTo(searchResults.getResources().size());
        }

        @Test
        void getGroupsInOtherZone_withZoneUserToken_returnsOkWithResults() throws Exception {
            String subdomain = new RandomValueStringGenerator(8).generate();
            UaaClientDetails bootstrapClient = null;
            MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(
                    subdomain, mockMvc, webApplicationContext, bootstrapClient, IdentityZoneHolder.getCurrentZoneId()
            );

            String zonedClientId = "zonedClientId";
            String zonedClientSecret = "zonedClientSecret";
            UaaClientDetails zonedClientDetails = (UaaClientDetails) MockMvcUtils.createClient(mockMvc, result.getZoneAdminToken(), zonedClientId, zonedClientSecret, Collections.singleton("oauth"),
                    Collections.singletonList("scim.read"), Arrays.asList("client_credentials", "password"), "scim.read", null, result.getIdentityZone());
            zonedClientDetails.setClientSecret(zonedClientSecret);

            ScimUser zoneUser = createUserAndAddToGroups(result.getIdentityZone(), Sets.newHashSet(Collections.singletonList("scim.read")));

            String basicDigestHeaderValue = "Basic " + new String(Base64.encodeBase64((zonedClientId + ":" + zonedClientSecret).getBytes()));
            MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                    .with(new SetServerNameRequestPostProcessor(result.getIdentityZone().getSubdomain() + ".localhost"))
                    .header("Authorization", basicDigestHeaderValue)
                    .param("grant_type", "password")
                    .param("client_id", zonedClientId)
                    .param("username", zoneUser.getUserName())
                    .param("password", "password")
                    .param("scope", "scim.read");
            MvcResult tokenResult = mockMvc.perform(oauthTokenPost).andExpect(status().isOk()).andReturn();
            OAuthToken oauthToken = JsonUtils.readValue(tokenResult.getResponse().getContentAsString(), OAuthToken.class);
            String zoneUserToken = oauthToken.accessToken;

            MockHttpServletRequestBuilder get = get("/Groups")
                    .with(new SetServerNameRequestPostProcessor(result.getIdentityZone().getSubdomain() + ".localhost"))
                    .header("Authorization", "Bearer " + zoneUserToken)
                    .param("attributes", "displayName")
                    .param("filter", "displayName co \"scim\"")
                    .contentType(MediaType.APPLICATION_JSON)
                    .accept(APPLICATION_JSON);
            MvcResult mvcResult = mockMvc.perform(get)
                    .andExpect(status().isOk())
                    .andReturn();

            SearchResults searchResults = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), SearchResults.class);
            assertThat(searchResults.getResources()).hasSameSizeAs(getSystemScopes("scim"));

            get = get("/Groups")
                    .with(new SetServerNameRequestPostProcessor(result.getIdentityZone().getSubdomain() + ".localhost"))
                    .header("Authorization", "Bearer " + zoneUserToken)
                    .contentType(MediaType.APPLICATION_JSON)
                    .accept(APPLICATION_JSON);
            mvcResult = mockMvc.perform(get)
                    .andExpect(status().isOk())
                    .andReturn();

            searchResults = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), SearchResults.class);
            assertThat(UserConfig.DEFAULT_ZONE_GROUPS.size() +
                    getSystemScopes(null).size() - 1).isEqualTo(searchResults.getResources().size());
        }
    }

    List<String> getSystemScopes(String containing) {
        List<String> systemScopes = ZoneManagementScopes.getSystemScopes();
        if (hasText(containing)) {
            return systemScopes.stream()
                    .filter(s -> s.contains(containing))
                    .toList();
        } else {
            return systemScopes;
        }
    }

    @Test
    void getGroupsWithMaxCountSizeWhenProvidedWithNonDefaultCountParams() throws Exception {
        for (int i = 0; i < 12; i++) {
            String displayName = "internal.read" + new RandomValueStringGenerator().generate();
            String externalGroup = "cn=java-developers,ou=scopes,dc=test,dc=com" + new RandomValueStringGenerator().generate();
            createGroup(null, displayName, externalGroup);
        }

        MockHttpServletRequestBuilder get = get("/Groups").param("count", "10")
                .header("Authorization", "Bearer " + scimReadToken)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(APPLICATION_JSON);

        MvcResult mvcResult = mockMvc.perform(get)
                .andExpect(status().isOk())
                .andReturn();

        SearchResults searchResults = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), SearchResults.class);
        assertThat(searchResults.getResources()).hasSize(5);
        assertThat(searchResults.getItemsPerPage()).isEqualTo(5);
        assertThat(searchResults.getTotalResults()).isGreaterThan(10);
    }

    @Test
    void getGroupsWithMaxCountSizeWhenProvidedWithNoCountParam() throws Exception {
        for (int i = 0; i < 12; i++) {
            String displayName = "internal.read" + new RandomValueStringGenerator().generate();
            String externalGroup = "cn=java-developers,ou=scopes,dc=test,dc=com" + new RandomValueStringGenerator().generate();
            createGroup(null, displayName, externalGroup);
        }

        MockHttpServletRequestBuilder get = get("/Groups")
                .header("Authorization", "Bearer " + scimReadToken)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(APPLICATION_JSON);

        MvcResult mvcResult = mockMvc.perform(get)
                .andExpect(status().isOk())
                .andReturn();

        SearchResults searchResults = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), SearchResults.class);
        assertThat(searchResults.getResources()).hasSize(5);
        assertThat(searchResults.getItemsPerPage()).isEqualTo(5);
        assertThat(searchResults.getTotalResults()).isGreaterThan(10);
    }

    @Test
    void getGroupsInvalidFilter() throws Exception {
        MockHttpServletRequestBuilder get = get("/Groups")
                .header("Authorization", "Bearer " + scimReadToken)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .param("filter", "blabla eq \"test\"");

        mockMvc.perform(get)
                .andExpect(status().isBadRequest());

        get = get("/Groups")
                .header("Authorization", "Bearer " + scimReadUserToken)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .param("filter", "blabla eq \"test\"");

        mockMvc.perform(get)
                .andExpect(status().isBadRequest());
    }

    @Test
    void getGroupsInvalidAttributes() throws Exception {
        String nonexistentAttribute = "displayBlaBla";

        MockHttpServletRequestBuilder get = get("/Groups")
                .header("Authorization", "Bearer " + scimReadToken)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .param("attributes", nonexistentAttribute);

        MvcResult mvcResult = mockMvc.perform(get)
                .andExpect(status().isOk())
                .andReturn();

        String body = mvcResult.getResponse().getContentAsString();
        List<Map<String, Object>> attList = (List) JsonUtils.readValue(body, Map.class).get("resources");
        for (Map<String, Object> attMap : attList) {
            assertThat(attMap).containsEntry(nonexistentAttribute, null);
        }
    }

    @Test
    void getExternalGroups() throws Exception {
        checkGetExternalGroups();
    }

    @Test
    void createExternalGroupMapUsingName() throws Exception {
        String displayName = "internal.read";
        String externalGroup = "cn=java-developers,ou=scopes,dc=test,dc=com";
        ResultActions result = createGroup(null, displayName, externalGroup);
        result.andExpect(status().isCreated());

        //add the newly added list to our expected list, and check again.
        int previousSize = defaultExternalMembers.size();
        ArrayList<String> list = new ArrayList<>(defaultExternalMembers);
        list.add(displayName + "|" + externalGroup);
        defaultExternalMembers = list;
        assertThat(defaultExternalMembers).hasSize(previousSize + 1);
        checkGetExternalGroups();
    }

    @Test
    void createExternalGroupMapUsingNameAlreadyExists() throws Exception {
        String displayName = "internal.read";
        String externalGroup = "cn=developers,ou=scopes,dc=test,dc=com";
        ResultActions result = createGroup(null, displayName, externalGroup);
        //we don't throw in JdbcScimGroupExternalMembershipManager.java
        //result.andExpect(status().isConflict());
        result.andExpect(status().isCreated());
    }

    @Test
    void createExternalGroupMapNameDoesNotExists() throws Exception {
        String displayName = "internal.read" + "sdasdas";
        String externalGroup = "cn=developers,ou=scopes,dc=test,dc=com";
        ResultActions result = createGroup(null, displayName, externalGroup);
        result.andExpect(status().isNotFound());
    }

    @Test
    void createExternalGroupMapNameIsNull() throws Exception {
        String externalGroup = "cn=developers,ou=scopes,dc=test,dc=com";
        ResultActions result = createGroup(null, null, externalGroup);
        result.andExpect(status().isNotFound());
    }

    @Test
    void createExternalGroupMapUsingId() throws Exception {
        String displayName = "internal.read";
        String groupId = getGroupId(displayName);
        String externalGroup = "cn=java-developers,ou=scopes,dc=test,dc=com";

        ResultActions result = createGroup(groupId, null, externalGroup);
        result.andExpect(status().isCreated());

        //add the newly added list to our expected list, and check again.
        int previousSize = defaultExternalMembers.size();
        ArrayList<String> list = new ArrayList<>(defaultExternalMembers);
        list.add(displayName + "|" + externalGroup);
        defaultExternalMembers = list;
        assertThat(defaultExternalMembers).hasSize(previousSize + 1);
        checkGetExternalGroups();
    }

    @Test
    void create_and_update_group_description() throws Exception {
        String name = new RandomValueStringGenerator().generate();
        ScimGroup group = new ScimGroup(name);
        group.setZoneId("some-other-zone");
        group.setDescription(name + "-description");

        String content = JsonUtils.writeValueAsString(group);
        MockHttpServletRequestBuilder action = MockMvcRequestBuilders.post("/Groups")
                .header("Authorization", "Bearer " + scimWriteToken)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(content);

        ScimGroup newGroup =
                JsonUtils.readValue(
                        mockMvc.perform(action)
                                .andExpect(status().isCreated())
                                .andReturn().getResponse().getContentAsString(),
                        ScimGroup.class
                );
        assertThat(newGroup).isNotNull();
        assertThat(newGroup.getId()).isNotNull();
        assertThat(newGroup.getZoneId()).isEqualTo(IdentityZone.getUaaZoneId());
        assertThat(newGroup.getDisplayName()).isEqualTo(group.getDisplayName());
        assertThat(newGroup.getDescription()).isEqualTo(group.getDescription());

        group.setDescription(name + "-description-updated");
        newGroup.setDescription(group.getDescription());

        content = JsonUtils.writeValueAsString(newGroup);
        action = MockMvcRequestBuilders.put("/Groups/" + newGroup.getId())
                .header("Authorization", "Bearer " + scimWriteToken)
                .header("If-Match", newGroup.getVersion())
                .contentType(MediaType.APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(content);

        newGroup =
                JsonUtils.readValue(
                        mockMvc.perform(action)
                                .andExpect(status().isOk())
                                .andReturn().getResponse().getContentAsString(),
                        ScimGroup.class
                );

        assertThat(newGroup).isNotNull();
        assertThat(newGroup.getId()).isNotNull();
        assertThat(newGroup.getZoneId()).isEqualTo(IdentityZone.getUaaZoneId());
        assertThat(newGroup.getDisplayName()).isEqualTo(group.getDisplayName());
        assertThat(newGroup.getDescription()).isEqualTo(group.getDescription());

    }

    protected ResultActions createGroup(String id, String name, String externalName) throws Exception {
        return createGroup(id, name, externalName, null);
    }

    protected ResultActions createGroup(String id, String name, String externalName, String origin) throws Exception {
        ScimGroupExternalMember em = new ScimGroupExternalMember();
        if (id != null) {
            em.setGroupId(id);
        }
        if (externalName != null) {
            em.setExternalGroup(externalName);
        }
        if (name != null) {
            em.setDisplayName(name);
        }
        if (origin != null) {
            em.setOrigin(origin);
        }
        String content = JsonUtils.writeValueAsString(em);
        MockHttpServletRequestBuilder post = MockMvcRequestBuilders.post("/Groups/External")
                .header("Authorization", "Bearer " + scimWriteToken)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(content);

        return mockMvc.perform(post);
    }

    @Test
    void deleteExternalGroupMapUsingNameDeprecatedAPI() throws Exception {
        String displayName = "internal.read";
        String externalGroup = "cn=developers,ou=scopes,dc=test,dc=com";
        ScimGroupExternalMember em = new ScimGroupExternalMember();
        em.setDisplayName(displayName);
        em.setExternalGroup(externalGroup);

        MockHttpServletRequestBuilder delete = MockMvcRequestBuilders.delete("/Groups/External/" + displayName + "/" + externalGroup)
                .header("Authorization", "Bearer " + scimWriteToken)
                .accept(APPLICATION_JSON);

        ResultActions result = mockMvc.perform(delete);
        result.andExpect(status().isOk());

        //remove the deleted map from our expected list, and check again.
        int previousSize = defaultExternalMembers.size();
        ArrayList<String> list = new ArrayList<>(defaultExternalMembers);
        assertThat(list.remove(displayName + "|" + externalGroup)).isTrue();
        defaultExternalMembers = list;
        assertThat(defaultExternalMembers).hasSize(previousSize - 1);
        checkGetExternalGroups();
    }

    @Test
    void deleteExternalGroupMapUsingName() throws Exception {
        String displayName = "internal.read";
        String externalGroup = "cn=developers,ou=scopes,dc=test,dc=com";
        ScimGroupExternalMember em = new ScimGroupExternalMember();
        em.setDisplayName(displayName);
        em.setExternalGroup(externalGroup);

        MockHttpServletRequestBuilder post = MockMvcRequestBuilders.delete("/Groups/External/displayName/" + displayName + "/externalGroup/" + externalGroup + "/origin/ldap")
                .header("Authorization", "Bearer " + scimWriteToken)
                .accept(APPLICATION_JSON);

        ResultActions result = mockMvc.perform(post);
        result.andExpect(status().isOk());

        //remove the deleted map from our expected list, and check again.
        int previousSize = defaultExternalMembers.size();
        ArrayList<String> list = new ArrayList<>(defaultExternalMembers);
        assertThat(list.remove(displayName + "|" + externalGroup)).isTrue();
        defaultExternalMembers = list;
        assertThat(defaultExternalMembers).hasSize(previousSize - 1);
        checkGetExternalGroups();
    }

    @Test
    void deleteExternalGroupMapUsingNonExistentName() throws Exception {
        String displayName = "internal.read.nonexistent";
        String externalGroup = "cn=developers,ou=scopes,dc=test,dc=com";
        ScimGroupExternalMember em = new ScimGroupExternalMember();
        em.setDisplayName(displayName);
        em.setExternalGroup(externalGroup);

        MockHttpServletRequestBuilder post = MockMvcRequestBuilders.delete("/Groups/External/displayName/" + displayName + "/externalGroup/" + externalGroup + "/origin/ldap")
                .header("Authorization", "Bearer " + scimWriteToken)
                .accept(APPLICATION_JSON);

        ResultActions result = mockMvc.perform(post);
        result.andExpect(status().isNotFound());
    }

    @Test
    void deleteExternalGroupMapUsingIdDeprecatedAPI() throws Exception {
        String displayName = "internal.read";
        String externalGroup = "cn=developers,ou=scopes,dc=test,dc=com";
        String groupId = getGroupId(displayName);

        MockHttpServletRequestBuilder post = MockMvcRequestBuilders.delete("/Groups/External/id/" + groupId + "/" + externalGroup)
                .header("Authorization", "Bearer " + scimWriteToken)
                .accept(APPLICATION_JSON);

        ResultActions result = mockMvc.perform(post);
        result.andExpect(status().isOk());

        //remove the deleted map from our expected list, and check again.
        int previousSize = defaultExternalMembers.size();
        ArrayList<String> list = new ArrayList<>(defaultExternalMembers);
        assertThat(list.remove(displayName + "|" + externalGroup)).isTrue();
        defaultExternalMembers = list;
        assertThat(defaultExternalMembers).hasSize(previousSize - 1);
        checkGetExternalGroups();
    }

    @Test
    void deleteExternalGroupMapUsingId() throws Exception {
        String displayName = "internal.read";
        String externalGroup = "cn=developers,ou=scopes,dc=test,dc=com";
        String groupId = getGroupId(displayName);

        MockHttpServletRequestBuilder post = MockMvcRequestBuilders.delete("/Groups/External/groupId/" + groupId + "/externalGroup/" + externalGroup + "/origin/uaa")
                .header("Authorization", "Bearer " + scimWriteToken)
                .accept(APPLICATION_JSON);

        ResultActions result = mockMvc.perform(post);
        result.andExpect(status().isNotFound());

        post = MockMvcRequestBuilders.delete("/Groups/External/groupId/" + groupId + "/externalGroup/" + externalGroup + "/origin/" + LDAP)
                .header("Authorization", "Bearer " + scimWriteToken)
                .accept(APPLICATION_JSON);

        result = mockMvc.perform(post);
        result.andExpect(status().isOk());

        //remove the deleted map from our expected list, and check again.
        int previousSize = defaultExternalMembers.size();
        ArrayList<String> list = new ArrayList<>(defaultExternalMembers);
        assertThat(list.remove(displayName + "|" + externalGroup)).isTrue();
        defaultExternalMembers = list;
        assertThat(defaultExternalMembers).hasSize(previousSize - 1);
        checkGetExternalGroups();
    }

    @Test
    void deleteExternalGroupMapUsingNonExistentId() throws Exception {
        String externalGroup = "cn=developers,ou=scopes,dc=test,dc=com";
        String groupId = "non-existent";

        MockHttpServletRequestBuilder post = MockMvcRequestBuilders.delete("/Groups/External/groupId/" + groupId + "/externalGroup/" + externalGroup + "/origin/ldap")
                .header("Authorization", "Bearer " + scimWriteToken)
                .accept(APPLICATION_JSON);

        ResultActions result = mockMvc.perform(post);
        result.andExpect(status().isNotFound());
    }

    @Test
    void deleteExternalGroupMapUsingReadToken() throws Exception {
        String displayName = "internal.read";
        String externalGroup = "cn=developers,ou=scopes,dc=test,dc=com";
        String groupId = getGroupId(displayName);

        MockHttpServletRequestBuilder post = MockMvcRequestBuilders.delete("/Groups/External/id/" + groupId + "/" + externalGroup + "/origin/ldap")
                .header("Authorization", "Bearer " + scimReadToken)
                .accept(APPLICATION_JSON);

        ResultActions result = mockMvc.perform(post);
        result.andExpect(status().isForbidden());

        checkGetExternalGroups();
    }

    @Test
    void get_group_membership() throws Exception {
        String groupId = getGroupId("scim.read");
        MockHttpServletRequestBuilder get = get("/Groups/" + groupId + "/members/" + scimUser.getId())
                .header("Authorization", "Bearer " + scimReadToken);
        MvcResult mvcResult = mockMvc.perform(get)
                .andExpect(status().isOk())
                .andReturn();
        ScimGroupMember scimGroupMember = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), ScimGroupMember.class);
        assertThat(scimGroupMember).isNotNull();
        assertThat(scimGroupMember.getMemberId()).isEqualTo(scimUser.getId());
    }

    @Test
    void get_group_membership_user_not_member_of_group() throws Exception {
        String groupId = getGroupId("scim.read");
        MockHttpServletRequestBuilder get = get("/Groups/" + groupId + "/members/id-of-random-user")
                .header("Authorization", "Bearer " + scimReadToken);
        mockMvc.perform(get)
                .andExpect(status().isNotFound())
                .andReturn();
    }

    @Test
    void get_group_membership_nonexistent_group() throws Exception {
        MockHttpServletRequestBuilder get = get("/Groups/nonexistent-group-id/members/" + scimUser.getId())
                .header("Authorization", "Bearer " + scimReadToken);
        mockMvc.perform(get)
                .andExpect(status().isNotFound())
                .andReturn();
    }

    @Test
    void get_group_membership_nonexistent_user() throws Exception {
        String groupId = getGroupId("scim.read");
        MockHttpServletRequestBuilder get = get("/Groups/" + groupId + "/members/non-existent-user")
                .header("Authorization", "Bearer " + scimReadToken);
        mockMvc.perform(get)
                .andExpect(status().isNotFound())
                .andReturn();
    }

    @Test
    void get_all_group_memberships() throws Exception {
        String groupName = "random." + new RandomValueStringGenerator().generate();
        ScimGroup group = new ScimGroup(groupName);
        group = MockMvcUtils.createGroup(mockMvc, scimWriteToken, group);
        String groupId = getGroupId(groupName);
        assertThat(groupId).isEqualTo(group.getId());

        scimUser = createUserAndAddToGroups(IdentityZone.getUaa(), Sets.newHashSet(Collections.singletonList(groupName)));

        ScimUser secondUser = createUserAndAddToGroups(IdentityZone.getUaa(), Collections.singleton(groupName));
        ScimGroup innerGroup = createGroupWithinGroups(IdentityZone.getUaa(), Collections.singleton(groupName));

        MockHttpServletRequestBuilder get = get("/Groups/" + groupId + "/members/")
                .header("Authorization", "Bearer " + scimReadToken);
        MvcResult mvcResult = mockMvc.perform(get)
                .andExpect(status().isOk())
                .andReturn();
        String responseContent = mvcResult.getResponse().getContentAsString();
        List<Object> listMembers = JsonUtils.readValue(responseContent, new TypeReference<List<Object>>() {
        });
        Set<String> retrievedMembers = listMembers.stream().map(JsonUtils::writeValueAsString).collect(Collectors.toSet());

        assertThat(retrievedMembers).contains(
                JsonUtils.writeValueAsString(new ScimGroupMember(innerGroup.getId(), ScimGroupMember.Type.GROUP)),
                JsonUtils.writeValueAsString(new ScimGroupMember(secondUser.getId(), ScimGroupMember.Type.USER)),
                JsonUtils.writeValueAsString(new ScimGroupMember(scimUser.getId(), ScimGroupMember.Type.USER))
        );
    }

    @Test
    void get_group_memberships_with_entities() throws Exception {

        String groupName = "random." + new RandomValueStringGenerator().generate();
        ScimGroup group = new ScimGroup(groupName);
        group = MockMvcUtils.createGroup(mockMvc, scimWriteToken, group);
        String groupId = getGroupId(groupName);
        assertThat(groupId).isEqualTo(group.getId());

        scimUser = createUserAndAddToGroups(IdentityZone.getUaa(), Sets.newHashSet(Collections.singletonList(groupName)));

        ScimUser secondUser = createUserAndAddToGroups(IdentityZone.getUaa(), Collections.singleton(groupName));
        ScimGroup innerGroup = createGroupWithinGroups(IdentityZone.getUaa(), Collections.singleton(groupName));

        MockHttpServletRequestBuilder get = get("/Groups/" + groupId + "/members/")
                .header("Authorization", "Bearer " + scimReadToken)
                .param("returnEntities", "true");
        MvcResult mvcResult = mockMvc.perform(get)
                .andExpect(status().isOk())
                .andReturn();
        String responseContent = mvcResult.getResponse().getContentAsString();
        List<Object> listMembers = JsonUtils.readValue(responseContent, new TypeReference<List<Object>>() {
        });
        Set<String> retrievedMembers = listMembers.stream().map(JsonUtils::writeValueAsString).collect(Collectors.toSet());

        assertThat(retrievedMembers).contains(
                JsonUtils.writeValueAsString(new ScimGroupMember(innerGroup)),
                JsonUtils.writeValueAsString(new ScimGroupMember(secondUser)),
                JsonUtils.writeValueAsString(new ScimGroupMember(scimUser))
        );
    }

    @Test
    void get_group_memberships_for_nonexistent_group() throws Exception {
        MockHttpServletRequestBuilder get = get("/Groups/nonexistent-group-id/members/")
                .header("Authorization", "Bearer " + scimReadToken);
        mockMvc.perform(get)
                .andExpect(status().isNotFound())
                .andReturn();
    }

    @Test
    void add_member_to_group() throws Exception {
        ScimUser user = createUserAndAddToGroups(IdentityZone.getUaa(), Collections.emptySet());
        String groupId = getGroupId("scim.read");
        ScimGroupMember scimGroupMember = new ScimGroupMember(user.getId(), ScimGroupMember.Type.USER);
        MockHttpServletRequestBuilder post = post("/Groups/" + groupId + "/members")
                .header("Authorization", "Bearer " + scimWriteToken)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .content(JsonUtils.writeValueAsString(scimGroupMember));
        String responseBody = mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        assertThat(responseBody).isEqualTo(JsonUtils.writeValueAsString(scimGroupMember));
    }

    @Test
    void add_member_to_group_with_useless_role() throws Exception {
        ScimUser user = createUserAndAddToGroups(IdentityZone.getUaa(), Collections.emptySet());
        String groupId = getGroupId("scim.read");
        ScimGroupMember scimGroupMember = new ScimGroupMember(user.getId(), ScimGroupMember.Type.USER);
        JsonNode memberAsJson = JsonUtils.readTree(JsonUtils.writeValueAsString(scimGroupMember));
        ((ObjectNode) memberAsJson).putArray("roles").add("READER").add("WRITER");
        String updatedMember = JsonUtils.writeValueAsString(memberAsJson);

        MockHttpServletRequestBuilder post = post("/Groups/" + groupId + "/members")
                .header("Authorization", "Bearer " + scimWriteToken)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .content(updatedMember);
        String responseBody = mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        assertThat(responseBody).isEqualTo(JsonUtils.writeValueAsString(scimGroupMember));
    }

    @Test
    void add_member_to_group_twice() throws Exception {
        ScimUser user = createUserAndAddToGroups(IdentityZone.getUaa(), Collections.emptySet());
        String groupId = getGroupId("scim.read");
        ScimGroupMember scimGroupMember = new ScimGroupMember(user.getId(), ScimGroupMember.Type.USER);
        mockMvc.perform(post("/Groups/" + groupId + "/members")
                        .header("Authorization", "Bearer " + scimWriteToken)
                        .header("Content-Type", APPLICATION_JSON_VALUE)
                        .content(JsonUtils.writeValueAsString(scimGroupMember)))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/Groups/" + groupId + "/members")
                        .header("Authorization", "Bearer " + scimWriteToken)
                        .header("Content-Type", APPLICATION_JSON_VALUE)
                        .content(JsonUtils.writeValueAsString(scimGroupMember)))
                .andExpect(status().isConflict());
    }

    @Test
    void delete_member_from_group() throws Exception {
        ScimUser user = createUserAndAddToGroups(IdentityZone.getUaa(), Collections.singleton("scim.read"));
        String groupId = getGroupId("scim.read");

        String deleteResponseBody = mockMvc.perform(delete("/Groups/" + groupId + "/members/" + user.getId())
                        .header("Authorization", "Bearer " + scimWriteToken)
                        .header("Content-Type", APPLICATION_JSON_VALUE))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

        ScimGroupMember deletedMember = JsonUtils.readValue(deleteResponseBody, ScimGroupMember.class);

        assertThat(deletedMember.getMemberId()).isEqualTo(user.getId());
    }

    @Test
    void delete_member_from_nonexistent_group() throws Exception {
        ScimUser user = createUserAndAddToGroups(IdentityZone.getUaa(), Collections.singleton("scim.read"));

        mockMvc.perform(delete("/Groups/nonexistent-group/members/" + user.getId())
                        .header("Authorization", "Bearer " + scimWriteToken)
                        .header("Content-Type", APPLICATION_JSON_VALUE))
                .andExpect(status().isNotFound());
    }

    @Test
    void delete_user_not_member_of_group() throws Exception {
        String groupId = getGroupId("uaa.admin");
        mockMvc.perform(delete("/Groups/" + groupId + "/members/" + scimUser.getId())
                        .header("Authorization", "Bearer " + scimWriteToken)
                        .header("Content-Type", APPLICATION_JSON_VALUE))
                .andExpect(status().isNotFound());
    }

    @Test
    void delete_nonexistent_user() throws Exception {
        mockMvc.perform(delete("/Groups/nonexistent-group/members/non-existent-user")
                        .header("Authorization", "Bearer " + scimWriteToken)
                        .header("Content-Type", APPLICATION_JSON_VALUE))
                .andExpect(status().isNotFound());
    }

    @Test
    void patch_has_one_path() throws Exception {
        mockMvc.perform(patch("/Group/groupId/members")
                        .header("Authorization", "Bearer " + scimWriteToken)
                        .header("Content-Type", APPLICATION_JSON_VALUE))
                .andDo(print())
                .andExpect(header().string("Location", "http://localhost/login?error=invalid_login_request"))
                .andExpect(status().isFound()); //gets caught by the ui filter for unknown URIs but wantsJson;
    }

    @Test
    void add_member_bad_token() throws Exception {
        ScimUser user = createUserAndAddToGroups(IdentityZone.getUaa(), Collections.emptySet());
        String groupId = getGroupId("scim.read");
        String anyOldToken = testClient.getClientCredentialsOAuthAccessToken(clientId, clientSecret, "other.scope");

        ScimGroupMember scimGroupMember = new ScimGroupMember(user.getId(), ScimGroupMember.Type.USER);

        MockHttpServletRequestBuilder post = post("/Groups/" + groupId + "/members")
                .header("Authorization", "Bearer " + anyOldToken)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .content(JsonUtils.writeValueAsString(scimGroupMember));
        mockMvc.perform(post)
                .andExpect(status().isForbidden());
    }

    @Test
    void add_member_to_nonexistent_group() throws Exception {
        ScimUser user = createUserAndAddToGroups(IdentityZone.getUaa(), Collections.emptySet());
        ScimGroupMember scimGroupMember = new ScimGroupMember(user.getId(), ScimGroupMember.Type.USER);
        MockHttpServletRequestBuilder post = post("/Groups/nonexistent-group-id/members")
                .header("Authorization", "Bearer " + scimWriteToken)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .content(JsonUtils.writeValueAsString(scimGroupMember));
        mockMvc.perform(post)
                .andExpect(status().isNotFound());
    }

    @Test
    void add_nonexistent_user_to_group() throws Exception {
        String groupId = getGroupId("scim.read");
        ScimGroupMember scimGroupMember = new ScimGroupMember("random-user-id", ScimGroupMember.Type.USER);
        MockHttpServletRequestBuilder post = post("/Groups/" + groupId + "/members")
                .header("Authorization", "Bearer " + scimWriteToken)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .content(JsonUtils.writeValueAsString(scimGroupMember));
        mockMvc.perform(post)
                .andExpect(status().isNotFound());
    }

    @Test
    void getExternalGroupsPagination() throws Exception {
        checkGetExternalGroupsPagination(1);
        checkGetExternalGroupsPagination(2);
        checkGetExternalGroupsPagination(3);
        checkGetExternalGroupsPagination(4);
        checkGetExternalGroupsPagination(5);
        checkGetExternalGroupsPagination(6);
        checkGetExternalGroupsPagination(100);
    }

    @Test
    void external_group_filtering() throws Exception {
        //add a group of another origin
        createGroup(null, "internal.read", "external-group-name", "other-origin").andExpect(status().isCreated());

        //get all results
        assertThat(performExternalGroupFilter(getListExternalGroupMethod(), HttpStatus.OK)).hasSize(6);

        //filter using origin parameter
        assertThat(performExternalGroupFilter(getListExternalGroupMethod().param("origin", "other-origin"), HttpStatus.OK)).hasSize(1);
        assertThat(performExternalGroupFilter(getListExternalGroupMethod().param("origin", OriginKeys.LDAP), HttpStatus.OK)).hasSize(5);

        //filter using externalGroup parameter
        assertThat(performExternalGroupFilter(getListExternalGroupMethod().param("externalGroup", "external-group-name"), HttpStatus.OK)).hasSize(1);

        //filter using both
        assertThat(performExternalGroupFilter(getListExternalGroupMethod().param("externalGroup", "external-group-name").param("origin", OriginKeys.LDAP), HttpStatus.OK)).isEmpty();
        assertThat(performExternalGroupFilter(getListExternalGroupMethod().param("externalGroup", "external-group-name").param("origin", "other-origin"), HttpStatus.OK)).hasSize(1);

        //filter using filter
        assertThat(performExternalGroupFilter(getListExternalGroupMethod().param("filter", "externalGroup eq \"external-group-name\""), HttpStatus.OK)).hasSize(1);
        assertThat(performExternalGroupFilter(getListExternalGroupMethod().param("filter", "origin eq \"ldap\""), HttpStatus.OK)).hasSize(5);
        assertThat(performExternalGroupFilter(getListExternalGroupMethod().param("filter", "externalGroup eq \"external-group-name\" and origin eq \"ldap\""), HttpStatus.OK)).isEmpty();
        assertThat(performExternalGroupFilter(getListExternalGroupMethod().param("filter", "externalGroup eq \"external-group-name\" and origin eq \"other-origin\""), HttpStatus.OK)).hasSize(1);

        //invalid parameter combinations
        performExternalGroupFilter(getListExternalGroupMethod().param("filter", "origin eq \"ldap\"").param("origin", "value"), HttpStatus.BAD_REQUEST);
        performExternalGroupFilter(getListExternalGroupMethod().param("filter", "origin eq \"ldap\"").param("externalGroup", "value"), HttpStatus.BAD_REQUEST);

        //invalid filters
        performExternalGroupFilter(getListExternalGroupMethod().param("filter", "origin co \"ldap\""), HttpStatus.BAD_REQUEST);
        performExternalGroupFilter(getListExternalGroupMethod().param("filter", "origin sw \"ldap\""), HttpStatus.BAD_REQUEST);
        performExternalGroupFilter(getListExternalGroupMethod().param("filter", "origin eq \"ldap\""), HttpStatus.OK);
    }

    MockHttpServletRequestBuilder getListExternalGroupMethod() {
        return get("/Groups/External")
                .param("startIndex", String.valueOf(0))
                .param("count", String.valueOf(1000))
                .header("Authorization", "Bearer " + scimReadToken)
                .accept(APPLICATION_JSON);
    }

    List<Map<String, String>> performExternalGroupFilter(MockHttpServletRequestBuilder get, HttpStatus status) throws Exception {
        ResultActions result = mockMvc.perform(get);
        result.andExpect(status().is(status.value()));
        if (status.equals(HttpStatus.OK)) {
            String content = result.andReturn().getResponse().getContentAsString();
            Map<String, Object> map = JsonUtils.readValue(content, new TypeReference<Map<String, Object>>() {
            });
            return (List<Map<String, String>>) map.get("resources");
        } else {
            return null;
        }
    }

    void checkGetExternalGroupsPagination(int pageSize) throws Exception {
        List<SearchResults<ScimGroupExternalMember>> pages = new ArrayList<>();

        for (int start = 1; start <= databaseExternalMembers.size(); start += pageSize) {
            MockHttpServletRequestBuilder get = get("/Groups/External")
                    .param("startIndex", String.valueOf(start))
                    .param("count", String.valueOf(pageSize))
                    .header("Authorization", "Bearer " + scimReadToken)
                    .accept(APPLICATION_JSON);

            ResultActions result = mockMvc.perform(get);
            result.andExpect(status().isOk());
            String content = result.andReturn().getResponse().getContentAsString();
            SearchResults<ScimGroupExternalMember> page = null;

            Map<String, Object> map = JsonUtils.readValue(content, Map.class);
            List<Map<String, String>> resources = (List<Map<String, String>>) map.get("resources");
            int startIndex = Integer.parseInt(map.get("startIndex").toString());
            int itemsPerPage = Integer.parseInt(map.get("itemsPerPage").toString());
            int totalResults = Integer.parseInt(map.get("totalResults").toString());
            List<ScimGroupExternalMember> memberList = new ArrayList<>();
            for (Map<String, String> m : resources) {
                ScimGroupExternalMember sgm = new ScimGroupExternalMember();
                sgm.setGroupId(m.get("groupId"));
                sgm.setDisplayName(m.get("displayName"));
                sgm.setExternalGroup(m.get("externalGroup"));
                sgm.setOrigin(m.get("origin"));
                memberList.add(sgm);
            }
            page = new SearchResults<>((List<String>) map.get("schemas"), memberList, startIndex, itemsPerPage, totalResults);
            pages.add(page);
        }

        List<ScimGroupExternalMember> members = pages.stream()
                .flatMap(p -> p.getResources().stream())
                .toList();

        validateDbMembers(databaseExternalMembers, members);
    }

    void checkGetExternalGroups() throws Exception {
        String path = "/Groups/External";
        checkGetExternalGroups(path);
        path = "/Groups/External";
        checkGetExternalGroups(path);
    }

    void checkGetExternalGroups(String path) throws Exception {
        MockHttpServletRequestBuilder get = get(path)
                .header("Authorization", "Bearer " + scimReadToken)
                .accept(APPLICATION_JSON);

        ResultActions result = mockMvc.perform(get);
        result.andExpect(status().isOk());
        String content = result.andReturn().getResponse().getContentAsString();
        SearchResults<ScimGroupExternalMember> members = null;

        Map<String, Object> map = JsonUtils.readValue(content, Map.class);
        List<Map<String, String>> resources = (List<Map<String, String>>) map.get("resources");
        int startIndex = Integer.parseInt(map.get("startIndex").toString());
        int itemsPerPage = Integer.parseInt(map.get("itemsPerPage").toString());
        int totalResults = Integer.parseInt(map.get("totalResults").toString());
        List<ScimGroupExternalMember> memberList = new ArrayList<>();
        for (Map<String, String> m : resources) {
            ScimGroupExternalMember sgm = new ScimGroupExternalMember();
            sgm.setGroupId(m.get("groupId"));
            sgm.setDisplayName(m.get("displayName"));
            sgm.setExternalGroup(m.get("externalGroup"));
            sgm.setOrigin(m.get("origin"));
            memberList.add(sgm);
        }
        members = new SearchResults<>((List<String>) map.get("schemas"), memberList, startIndex, itemsPerPage, totalResults);
        assertThat(members).isNotNull();
        assertThat(members.getResources()).hasSameSizeAs(defaultExternalMembers);
        validateMembers(defaultExternalMembers, members.getResources());
    }

    String getGroupId(String displayName) {
        JdbcScimGroupProvisioning gp = (JdbcScimGroupProvisioning) webApplicationContext.getBean("scimGroupProvisioning");
        List<ScimGroup> result = gp.query("displayName eq \"" + displayName + "\"", IdentityZoneHolder.get().getId());
        if (result == null || result.isEmpty()) {
            throw new NullPointerException("Group not found:" + displayName);
        }
        if (result.size() > 1) {
            throw new IllegalStateException("Group name should be unique:" + displayName);
        }
        return result.getFirst().getId();
    }

    void validateMembers(List<String> expected, Collection<ScimGroupExternalMember> actual) {
        List<ScimGroupExternalMember> members = new ArrayList<>();
        for (String s : expected) {
            String[] data = s.split("\\|");
            assertThat(data)
                    .isNotNull()
                    .hasSize(2);
            String displayName = data[0];
            String externalId = data[1];
            ScimGroupExternalMember mbr = new ScimGroupExternalMember("N/A", externalId);
            mbr.setDisplayName(displayName);
            mbr.setOrigin(OriginKeys.LDAP);
            members.add(mbr);
        }
        validateDbMembers(members, actual);
    }

    void validateDbMembers(Collection<ScimGroupExternalMember> expected, Collection<ScimGroupExternalMember> actual) {
        for (ScimGroupExternalMember s : expected) {
            final String displayName = s.getDisplayName();
            final String externalId = s.getExternalGroup();
            final String origin = s.getOrigin();
            boolean found = false;
            for (ScimGroupExternalMember m : actual) {
                assertThat(m.getDisplayName()).as("Display name can not be null").isNotNull();
                assertThat(m.getExternalGroup()).as("External ID can not be null").isNotNull();
                if (m.getDisplayName().equals(displayName) && m.getExternalGroup().equals(externalId) && m.getOrigin().equals(origin)) {
                    found = true;
                    break;
                }
            }
            assertThat(found).as("Did not find expected external group mapping:" + s).isTrue();
            assertThat(actual).as("The result set must contain exactly as many items as expected").hasSameSizeAs(expected);
        }
    }

    private ScimUser createUserAndAddToGroups(IdentityZone zone, Set<String> groupNames) {
        if (zone == null) {
            zone = IdentityZone.getUaa();
        }
        ScimUserProvisioning usersRepository = webApplicationContext.getBean(ScimUserProvisioning.class);
        ScimGroupProvisioning groupRepository = webApplicationContext.getBean(ScimGroupProvisioning.class);
        String email = "otheruser@" + generator.generate().toLowerCase() + ".com";
        ScimUser user = new ScimUser(null, email, "Other", "User");
        user.addEmail(email);
        user.setVerified(true);
        IdentityZone originalZone = IdentityZoneHolder.get();
        try {
            if (zone != null) {
                IdentityZoneHolder.set(zone);
            }
            user.setOrigin(OriginKeys.UAA);
            user = usersRepository.createUser(user, "password", IdentityZoneHolder.get().getId());
            ephemeralResources.add(new String[]{user.getId(), "USER"});

            Collection<ScimUser.Group> scimUserGroups = new LinkedList<>();
            for (String groupName : groupNames) {
                List<ScimGroup> scimGroups = groupRepository.query("displayName eq \"" + groupName + "\"", IdentityZoneHolder.get().getId());
                ScimUser.Group scimUserGroup;
                ScimGroup group;
                if (scimGroups == null || scimGroups.isEmpty()) {
                    group = new ScimGroup(null, groupName, IdentityZoneHolder.get().getId());
                    group = groupRepository.create(group, IdentityZoneHolder.get().getId());
                    scimUserGroup = new ScimUser.Group(group.getId(), groupName);
                } else {
                    group = scimGroups.getFirst();
                    scimUserGroup = new ScimUser.Group(scimGroups.getFirst().getId(), groupName);
                }
                scimUserGroups.add(scimUserGroup);
                ScimGroupMembershipManager scimGroupMembershipManager = webApplicationContext.getBean(ScimGroupMembershipManager.class);
                ScimGroupMember member = new ScimGroupMember(user.getId(), ScimGroupMember.Type.USER);
                try {
                    scimGroupMembershipManager.addMember(group.getId(), member, IdentityZoneHolder.get().getId());
                } catch (MemberAlreadyExistsException ignored) {
                }
            }
        } finally {
            IdentityZoneHolder.set(originalZone);
        }
        return user;
    }

    private ScimGroup createGroupWithinGroups(IdentityZone zone, Set<String> groupNames) {
        if (zone == null) {
            zone = IdentityZone.getUaa();
        }
        ScimGroupProvisioning groupRepository = webApplicationContext.getBean(ScimGroupProvisioning.class);
        ScimGroup newGroup = new ScimGroup(null, generator.generate(), zone.getId());
        IdentityZone originalZone = IdentityZoneHolder.get();
        try {
            if (zone != null) {
                IdentityZoneHolder.set(zone);
            }
            newGroup = groupRepository.create(newGroup, IdentityZoneHolder.get().getId());
            ephemeralResources.add(new String[]{newGroup.getId(), "GROUP"});

            Collection<ScimUser.Group> scimUserGroups = new LinkedList<>();
            for (String groupName : groupNames) {
                List<ScimGroup> scimGroups = groupRepository.query("displayName eq \"" + groupName + "\"", IdentityZoneHolder.get().getId());
                ScimUser.Group scimUserGroup;
                ScimGroup group;
                if (scimGroups == null || scimGroups.isEmpty()) {
                    group = new ScimGroup(null, groupName, IdentityZoneHolder.get().getId());
                    group = groupRepository.create(group, IdentityZoneHolder.get().getId());
                    scimUserGroup = new ScimUser.Group(group.getId(), groupName);
                } else {
                    group = scimGroups.getFirst();
                    scimUserGroup = new ScimUser.Group(scimGroups.getFirst().getId(), groupName);
                }
                scimUserGroups.add(scimUserGroup);
                ScimGroupMembershipManager scimGroupMembershipManager = webApplicationContext.getBean(ScimGroupMembershipManager.class);
                ScimGroupMember member = new ScimGroupMember(newGroup.getId(), ScimGroupMember.Type.GROUP);
                try {
                    scimGroupMembershipManager.addMember(group.getId(), member, IdentityZoneHolder.get().getId());
                } catch (MemberAlreadyExistsException ignored) {
                }
            }
        } finally {
            IdentityZoneHolder.set(originalZone);
        }
        return newGroup;
    }
}
