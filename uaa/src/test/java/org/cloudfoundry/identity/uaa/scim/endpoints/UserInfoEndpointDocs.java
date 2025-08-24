package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.mock.EndpointDocs;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.restdocs.snippet.Snippet;

import java.util.Arrays;
import java.util.Collections;

import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ATTRIBUTES;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.fieldWithPath;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class UserInfoEndpointDocs extends EndpointDocs {

    private final AlphanumericRandomValueStringGenerator generator = new AlphanumericRandomValueStringGenerator();
    private final String clientId = generator.generate().toLowerCase();
    private final String clientSecret = generator.generate().toLowerCase();
    private ScimUser user;

    @BeforeEach
    void setUp() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "clients.read clients.write clients.secret scim.read scim.write clients.admin");

        String authorities = "scim.read,scim.write,password.write,oauth.approvals,scim.create,openid";
        MockMvcUtils.createClient(mockMvc, adminToken, clientId, clientSecret, Collections.singleton("oauth"),
                Collections.singletonList("openid"), Arrays.asList("client_credentials", "password"), authorities);

        String userName = new AlphanumericRandomValueStringGenerator().generate() + "@test.org";
        user = new ScimUser(null, userName, "PasswordResetUserFirst", "PasswordResetUserLast");
        user.setPrimaryEmail(user.getUserName());
        user.setPassword("secr3T");
        ScimUser.PhoneNumber phoneNumber = new ScimUser.PhoneNumber("+15558880000");
        user.setPhoneNumbers(Collections.singletonList(phoneNumber));
        user = MockMvcUtils.createUser(mockMvc, adminToken, user);
    }

    @Test
    void get_user_info() throws Exception {
        String userInfoToken = testClient.getUserOAuthAccessToken(
                clientId,
                clientSecret,
                user.getUserName(),
                "secr3T",
                "openid"
        );

        Snippet requestHeaders = requestHeaders(
                headerWithName("Authorization")
                        .description("Access token with `openid` required. If the `" + USER_ATTRIBUTES + "` scope is in the token, " +
                                "the response object will contain custom attributes, if mapped to the external identity provider." +
                                "If  the `roles` scope is present, the response object will contain group memberships  from the external identity provider."

                        )
        );
        Snippet responseFields = responseFields(
                fieldWithPath("sub").description("Subject Identifier. A locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client."),
                fieldWithPath("user_id").description("Unique user identifier."),
                fieldWithPath("email").description("The user's email address."),
                fieldWithPath("email_verified").description("Indicates whether the user has verified their email address."),
                fieldWithPath("user_name").description("User name of the user, typically an email address."),
                fieldWithPath("given_name").description("The user's first name."),
                fieldWithPath("family_name").description("The user's last name."),
                fieldWithPath("name").description("A map with the user's first name and last name."),
                fieldWithPath("phone_number").description("The user's phone number."),
                fieldWithPath(ClaimConstants.PREVIOUS_LOGON_TIME).description("The unix epoch timestamp in milliseconds of 2nd to last successful user authentication.")
        );

        mockMvc.perform(get("/userinfo")
                        .header("Authorization", "Bearer " + userInfoToken))
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}",
                        preprocessResponse(prettyPrint()),
                        requestHeaders,
                        responseFields)
                );
    }
}
