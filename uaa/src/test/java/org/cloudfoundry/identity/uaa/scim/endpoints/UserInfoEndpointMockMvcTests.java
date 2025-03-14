package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.account.UserInfoResponse;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UserInfo;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.context.WebApplicationContext;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ROLES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ATTRIBUTES;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class UserInfoEndpointMockMvcTests {

    private final RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private final String clientId = generator.generate().toLowerCase();
    private final String clientSecret = generator.generate().toLowerCase();

    private ScimUser user;

    private List<String> roles;
    private MultiValueMap<String, String> userAttributes;

    @Autowired
    private WebApplicationContext webApplicationContext;
    @Autowired
    private MockMvc mockMvc;
    private TestClient testClient;

    @BeforeEach
    void setUp() throws Exception {
        testClient = new TestClient(mockMvc);

        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
                "admin",
                "adminsecret",
                "clients.read clients.write clients.secret scim.read scim.write clients.admin"
        );
        String authorities = "scim.read,scim.write,password.write,oauth.approvals,scim.create,openid";
        MockMvcUtils.createClient(
                mockMvc,
                adminToken,
                clientId,
                clientSecret,
                Collections.singleton("oauth"),
                Arrays.asList("openid", USER_ATTRIBUTES, ROLES),
                Arrays.asList("client_credentials", "password"),
                authorities
        );
        String userName = new RandomValueStringGenerator().generate() + "@test.org";
        user = new ScimUser(null, userName, "PasswordResetUserFirst", "PasswordResetUserLast");
        user.setPrimaryEmail(user.getUserName());
        user.setPassword("secr3T");
        user = MockMvcUtils.createUser(mockMvc, adminToken, user);
        webApplicationContext.getBean(UaaUserDatabase.class).updateLastLogonTime(user.getId());

        userAttributes = new LinkedMultiValueMap<>();
        userAttributes.add("single", "1");
        userAttributes.add("multi", "2");
        userAttributes.add("multi", "3");

        roles = Arrays.asList("role1", "role2", "role3");
        UserInfo userInfo = new UserInfo()
                .setUserAttributes(userAttributes)
                .setRoles(roles);

        webApplicationContext.getBean(UaaUserDatabase.class).storeUserInfo(user.getId(), userInfo);
    }

    @Test
    void testGetUserInfo() throws Exception {
        UserInfoResponse userInfoResponse = getUserInfo("openid");

        assertThat(userInfoResponse.getUserName()).isEqualTo(user.getUserName());
        assertThat(userInfoResponse.getFamilyName()).isEqualTo(user.getFamilyName());
        assertThat(userInfoResponse.getGivenName()).isEqualTo(user.getGivenName());
        assertThat(userInfoResponse.isEmailVerified()).isEqualTo(user.isVerified());

        String userId = userInfoResponse.getUserId();
        assertThat(userId).isNotNull();
        Long dbPreviousLogonTime = webApplicationContext.getBean(UaaUserDatabase.class).retrieveUserById(userId).getPreviousLogonTime();
        assertThat(userInfoResponse.getPreviousLogonSuccess()).isEqualTo(dbPreviousLogonTime);
    }

    @Test
    void testPostUserInfo() throws Exception {
        UserInfoResponse userInfoResponse = performUserInfoRequest(post("/userinfo"), "openid");

        assertThat(userInfoResponse.getUserName()).isEqualTo(user.getUserName());
    }

    @Test
    void attributesWithRolesAndUserAttributes() throws Exception {
        UserInfoResponse userInfo = getUserInfo("openid user_attributes roles");
        Map<String, List<String>> uas = userInfo.getUserAttributes();
        assertThat(uas)
                .isNotNull()
                .isEqualTo(userAttributes);

        Object r = userInfo.getRoles();
        assertThat(r)
                .isNotNull()
                .isEqualTo(roles);
    }

    @Test
    void attributesWithNoExtraScopes() throws Exception {
        UserInfoResponse userInfo = getUserInfo("openid");
        assertThat(userInfo.getUserAttributes()).isNull();
        assertThat(userInfo.getRoles()).isNull();
    }

    private UserInfoResponse getUserInfo(String scopes) throws Exception {
        return performUserInfoRequest(get("/userinfo"), scopes);
    }

    private UserInfoResponse performUserInfoRequest(MockHttpServletRequestBuilder request, String scopes) throws Exception {
        String userInfoToken = testClient.getUserOAuthAccessToken(
                clientId,
                clientSecret,
                user.getUserName(),
                "secr3T",
                scopes
        );

        MockHttpServletResponse response = mockMvc.perform(
                        request.header("Authorization", "Bearer " + userInfoToken))
                .andExpect(status().isOk())
                .andReturn().getResponse();

        return JsonUtils.readValue(
                response.getContentAsString(),
                UserInfoResponse.class
        );
    }

}
