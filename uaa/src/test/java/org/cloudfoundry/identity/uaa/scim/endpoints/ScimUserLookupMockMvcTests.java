package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class ScimUserLookupMockMvcTests {
    private final AlphanumericRandomValueStringGenerator generator = new AlphanumericRandomValueStringGenerator();
    private final String clientId = generator.generate().toLowerCase();
    private final String clientSecret = generator.generate().toLowerCase();

    @Autowired
    private TestClient testClient;
    @Autowired
    private MockMvc mockMvc;

    private String scimLookupIdUserToken;
    private String adminToken;

    private static String[][] testUsers;

    private ScimUser user;

    @BeforeEach
    void setUp() throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "clients.read clients.write clients.secret scim.read scim.write clients.admin");

        user = new ScimUser(null, new AlphanumericRandomValueStringGenerator().generate() + "@test.org", "PasswordResetUserFirst", "PasswordResetUserLast");
        user.setPrimaryEmail(user.getUserName());
        user.setPassword("secr3T");
        user = MockMvcUtils.createUser(this.mockMvc, adminToken, user);

        List<String> scopes = Arrays.asList("scim.userids", "cloud_controller.read");
        MockMvcUtils.createClient(this.mockMvc, adminToken, clientId, clientSecret, Collections.singleton("scim"), scopes, Arrays.asList("client_credentials", "password"), "uaa.none");
        scimLookupIdUserToken = testClient.getUserOAuthAccessToken(clientId, clientSecret, user.getUserName(), "secr3T", "scim.userids");
        if (testUsers == null) {
            testUsers = createUsers(adminToken);
        }
    }

    @Test
    void lookupIdFromUsername() throws Exception {
        String username = UaaTestAccounts.standard(null).getUserName();

        MockHttpServletRequestBuilder post = getIdLookupRequest(scimLookupIdUserToken, username, "eq");

        String body = mockMvc.perform(post)
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        validateLookupResults(new String[]{username}, body);
    }

    @Test
    void lookupUsingOnlyOrigin() throws Exception {
        String filter = "origin eq \"uaa\"";
        MockHttpServletRequestBuilder post = post("/ids/Users")
                .header("Authorization", "Bearer " + scimLookupIdUserToken)
                .accept(APPLICATION_JSON)
                .param("filter", filter)
                .param("startIndex", String.valueOf(1))
                .param("count", String.valueOf(50));

        mockMvc.perform(post)
                .andExpect(status().isBadRequest());
    }

    @Test
    void lookupId_DoesntReturnInactiveIdp_ByDefault() throws Exception {
        ScimUser scimUser = createInactiveIdp(new AlphanumericRandomValueStringGenerator().generate() + "test-origin");

        String filter = "(username eq \"" + user.getUserName() + "\" OR username eq \"" + scimUser.getUserName() + "\")";
        MockHttpServletRequestBuilder post = post("/ids/Users")
                .header("Authorization", "Bearer " + scimLookupIdUserToken)
                .accept(APPLICATION_JSON)
                .param("filter", filter);

        MockHttpServletResponse response = mockMvc.perform(post)
                .andExpect(status().isOk())
                .andReturn().getResponse();
        Map<String, Object> map = JsonUtils.readValue(response.getContentAsString(), Map.class);
        List<Map<String, Object>> resources = (List<Map<String, Object>>) map.get("resources");
        assertThat(resources).hasSize(1);
        assertThat(resources.getFirst()).doesNotContainEntry("origin", "test-origin");
    }

    @Test
    void lookupId_ReturnInactiveIdp_WithIncludeInactiveParam() throws Exception {
        ScimUser scimUser = createInactiveIdp(new AlphanumericRandomValueStringGenerator().generate() + "test-origin");

        String filter = "(username eq \"" + user.getUserName() + "\" OR username eq \"" + scimUser.getUserName() + "\")";
        MockHttpServletRequestBuilder post = post("/ids/Users")
                .header("Authorization", "Bearer " + scimLookupIdUserToken)
                .accept(APPLICATION_JSON)
                .param("filter", filter)
                .param("includeInactive", "true");

        MockHttpServletResponse response = mockMvc.perform(post)
                .andExpect(status().isOk())
                .andReturn().getResponse();
        Map<String, Object> map = JsonUtils.readValue(response.getContentAsString(), Map.class);
        List<Map<String, Object>> resources = (List<Map<String, Object>>) map.get("resources");
        assertThat(resources).hasSize(2);
    }

    @Test
    void lookupIdFromUsernameWithNoToken() throws Exception {
        String username = UaaTestAccounts.standard(null).getUserName();

        MockHttpServletRequestBuilder post = post("/ids/Users")
                .accept(APPLICATION_JSON)
                .param("filter", "username eq \"" + username + "\"")
                .param("startIndex", String.valueOf(1))
                .param("count", String.valueOf(100));

        mockMvc.perform(post)
                .andExpect(status().isUnauthorized());
    }

    @Test
    void lookupIdFromUsernameWithInvalidFilter() throws Exception {
        String username = UaaTestAccounts.standard(null).getUserName();

        MockHttpServletRequestBuilder post = getIdLookupRequest(scimLookupIdUserToken, username, "sw");

        mockMvc.perform(post)
                .andExpect(status().isBadRequest());

        post = getIdLookupRequest(scimLookupIdUserToken, username, "co");

        mockMvc.perform(post)
                .andExpect(status().isBadRequest());
    }

    @Test
    void lookupUserNameFromId() throws Exception {
        String id = testUsers[0][0];
        String email = testUsers[0][1];

        MockHttpServletRequestBuilder post = getUsernameLookupRequest(scimLookupIdUserToken, id);

        String body = mockMvc.perform(post)
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        validateLookupResults(new String[]{email}, body);
    }

    @Test
    void lookupIdFromUsernameWithIncorrectScope() throws Exception {
        String token = testClient.getUserOAuthAccessToken(clientId, clientSecret, user.getUserName(), "secr3T", "cloud_controller.read");
        String username = UaaTestAccounts.standard(null).getUserName();

        MockHttpServletRequestBuilder post = getIdLookupRequest(token, username, "eq");

        mockMvc.perform(post)
                .andExpect(status().isForbidden());
    }

    @Test
    void lookupUserNameFromIdWithIncorrectScope() throws Exception {
        String token = testClient.getUserOAuthAccessToken(clientId, clientSecret, user.getUserName(), "secr3T", "cloud_controller.read");
        String id = testUsers[0][0];

        MockHttpServletRequestBuilder post = getUsernameLookupRequest(token, id);

        mockMvc.perform(post)
                .andExpect(status().isForbidden());
    }

    @Test
    void lookupIdFromUsernamePagination() throws Exception {
        StringBuilder builder = new StringBuilder();
        String[] usernames = new String[25];
        int index = 0;
        for (String[] entry : testUsers) {
            builder.append("userName eq \"%s\" or ".formatted(entry[1]));
            usernames[index++] = entry[1];
        }
        String filter = builder.substring(0, builder.length() - 4);

        int pageSize = 5;
        for (int i = 0; i < testUsers.length; i += pageSize) {
            MockHttpServletRequestBuilder post = getIdLookupRequest(scimLookupIdUserToken, filter, i + 1, pageSize);
            String[] expectedUsername = new String[pageSize];
            System.arraycopy(usernames, i, expectedUsername, 0, pageSize);
            String body = mockMvc.perform(post)
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString();
            validateLookupResults(expectedUsername, body);
        }
    }

    private MockHttpServletRequestBuilder getIdLookupRequest(String token, String username, String operator) {
        String filter = "username %s \"%s\"".formatted(operator, username);
        return getIdLookupRequest(token, filter, 1, 100);
    }

    private MockHttpServletRequestBuilder getIdLookupRequest(String token, String filter, int startIndex, int count) {
        return post("/ids/Users")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .param("filter", filter)
                .param("startIndex", String.valueOf(startIndex))
                .param("count", String.valueOf(count));
    }

    private MockHttpServletRequestBuilder getUsernameLookupRequest(String token, String id) {
        String filter = "id eq \"%s\"".formatted(id);
        return post("/ids/Users")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .param("filter", filter);
    }

    private void validateLookupResults(String[] usernames, String body) {
        Map<String, Object> map = JsonUtils.readValue(body, Map.class);
        assertThat(map).as("Response should contain 'resources' object").containsKey("resources")
                .as("Response should contain 'startIndex' object").containsKey("startIndex")
                .as("Response should contain 'itemsPerPage' object").containsKey("itemsPerPage")
                .as("Response should contain 'totalResults' object").containsKey("totalResults");
        List<Map<String, Object>> resources = (List<Map<String, Object>>) map.get("resources");
        assertThat(resources).hasSameSizeAs(usernames);
        for (Map<String, Object> user : resources) {
            assertThat(user).as("Response should contain 'origin' object").containsKey(OriginKeys.ORIGIN)
                    .as("Response should contain 'id' object").containsKey("id")
                    .as("Response should contain 'userName' object").containsKey("userName");
            String userName = (String) user.get("userName");
            boolean found = false;
            for (String s : usernames) {
                if (s.equals(userName)) {
                    found = true;
                    break;
                }
            }
            assertThat(found).as("Received non requested user in result set '" + userName + "'").isTrue();
        }
        for (String s : usernames) {
            boolean found = false;
            for (Map<String, Object> user : resources) {
                String userName = (String) user.get("userName");
                if (s.equals(userName)) {
                    found = true;
                    break;
                }
            }
            assertThat(found).as("Missing user in result '" + s + "'").isTrue();
        }
    }

    private String[][] createUsers(String token) throws Exception {
        final int count = 25;
        String[][] result = new String[count][];
        for (int i = 0; i < count; i++) {
            String id = i > 9 ? "0" + i : "00" + i;
            String email = "joe" + id + "@" + generator.generate().toLowerCase() + ".com";

            ScimUser user = new ScimUser();
            user.setPassword("password");
            user.setUserName(email);
            user.setName(new ScimUser.Name("Joe", "User"));
            user.addEmail(email);

            byte[] requestBody = JsonUtils.writeValueAsBytes(user);
            MockHttpServletRequestBuilder post = post("/Users")
                    .header("Authorization", "Bearer " + token)
                    .contentType(APPLICATION_JSON)
                    .content(requestBody);

            String body = mockMvc.perform(post)
                    .andExpect(status().isCreated())
                    .andExpect(header().string("ETag", "\"0\""))
                    .andExpect(jsonPath("$.userName").value(email))
                    .andExpect(jsonPath("$.emails[0].value").value(email))
                    .andExpect(jsonPath("$.name.familyName").value("User"))
                    .andExpect(jsonPath("$.name.givenName").value("Joe"))
                    .andReturn().getResponse().getContentAsString();
            Map<String, Object> map = JsonUtils.readValue(body, Map.class);
            result[i] = new String[]{map.get("id").toString(), email};
        }
        return result;
    }

    private ScimUser createInactiveIdp(String originKey) throws Exception {
        String tokenToCreateIdp = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "idps.write");
        IdentityProvider inactiveIdentityProvider = MultitenancyFixture.identityProvider(originKey, "uaa");
        inactiveIdentityProvider.setActive(false);
        MockMvcUtils.createIdpUsingWebRequest(mockMvc, null, tokenToCreateIdp, inactiveIdentityProvider, status().isCreated());

        ScimUser scimUser = new ScimUser(null, new AlphanumericRandomValueStringGenerator().generate() + "@test.org", "test", "test");
        scimUser.setPrimaryEmail(scimUser.getUserName());
        scimUser.setPassword("secr3T");
        scimUser.setOrigin(originKey);
        scimUser = MockMvcUtils.createUserInZone(mockMvc, adminToken, scimUser, "");
        return scimUser;
    }
}
