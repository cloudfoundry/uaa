package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.restdocs.request.RequestDocumentation;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.utils;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.fieldWithPath;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.parameterWithName;
import static org.junit.Assert.assertEquals;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.pathParameters;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class UserInfoEndpointDocs extends InjectedMockContextTest {
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
    ScimUser.PhoneNumber phoneNumber = new ScimUser.PhoneNumber("+15558880000");
    user.setPhoneNumbers(Collections.singletonList(phoneNumber));
    user = utils().createUser(getMockMvc(), adminToken, user);
  }

  @Test
  public void test_Get_UserInfo() throws Exception {

    String userInfoToken = testClient.getUserOAuthAccessToken(
      clientId,
      clientSecret,
      user.getUserName(),
      "secr3T",
      "openid"
    );

    Snippet requestHeaders = requestHeaders(headerWithName("Authorization").description("Access token with openid required"));
    Snippet responseFields = responseFields(
      fieldWithPath("user_id").description("Unique user identifier."),
      fieldWithPath("email").description("The user's email address."),
      fieldWithPath("user_name").description("User name of the user, typically an email address."),
      fieldWithPath("given_name").description("The user's first name."),
      fieldWithPath("family_name").description("The user's last name."),
      fieldWithPath("name").description("A map with the user's first name and last name."),
      fieldWithPath("phone_number").description("The user's phone number")
      );

    getMockMvc().perform(
      get("/userinfo")
        .header("Authorization", "Bearer " + userInfoToken))
      .andExpect(status().isOk())
      .andDo(document("{ClassName}/{methodName}",
        preprocessResponse(prettyPrint()),
        requestHeaders,
        responseFields));
  }
}
