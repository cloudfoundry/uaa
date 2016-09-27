package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.utils;
import static org.junit.Assert.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class UserInfoEndpointMockMvcTests extends InjectedMockContextTest {

  private RandomValueStringGenerator generator = new RandomValueStringGenerator();
  private String clientId = generator.generate().toLowerCase();
  private String clientSecret = generator.generate().toLowerCase();

  private String adminToken;
  private TestClient testClient;

  private ScimUser user;
  private String userName;

  @Before
  public void setUp() throws Exception {
    testClient = new TestClient(getMockMvc());
    adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "clients.read clients.write clients.secret scim.read scim.write clients.admin");

    String authorities = "scim.read,scim.write,password.write,oauth.approvals,scim.create,openid";
    utils().createClient(this.getMockMvc(), adminToken, clientId, clientSecret, Collections.singleton("oauth"), Arrays.asList("openid"), Arrays.asList("client_credentials", "password"), authorities);

    userName = new RandomValueStringGenerator().generate()+"@test.org";
    user = new ScimUser(null, userName, "PasswordResetUserFirst", "PasswordResetUserLast");
    user.setPrimaryEmail(user.getUserName());
    user.setPassword("secr3T");
    user = utils().createUser(getMockMvc(), adminToken, user);
  }

  @Test
  public void testGetUserInfo() throws Exception {

    String userInfoToken = testClient.getUserOAuthAccessToken(
      clientId,
      clientSecret,
      user.getUserName(),
      "secr3T",
      "openid"
    );

    MockHttpServletResponse response = getMockMvc().perform(
      get("/userinfo")
        .header("Authorization", "Bearer " + userInfoToken))
      .andExpect(status().isOk())
      .andReturn().getResponse();

    Map<String, Object> map = JsonUtils.readValue(response.getContentAsString(), Map.class);
    assertEquals(user.getUserName(), map.get("user_name"));
    assertEquals(user.getFamilyName(), map.get("family_name"));
    assertEquals(user.getGivenName(), map.get("given_name"));
  }

}

