package org.cloudfoundry.identity.uaa.mock.token;

import org.cloudfoundry.identity.uaa.mock.EndpointDocs;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.jupiter.api.Test;
import org.springframework.restdocs.snippet.Snippet;

import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.ARRAY;
import static org.springframework.restdocs.payload.JsonFieldType.BOOLEAN;
import static org.springframework.restdocs.payload.JsonFieldType.NUMBER;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.formParameters;
import static org.springframework.restdocs.request.RequestDocumentation.parameterWithName;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class IntrospectTokenEndpointDocs extends EndpointDocs {

    @Test
    void introspectToken() throws Exception {

        String identityClientAccessToken = MockMvcUtils.getClientOAuthAccessToken(
                mockMvc,
                "app",
                "appclientsecret",
                "",
                true
        );

        String identityAccessToken = MockMvcUtils.getUserOAuthAccessToken(
                mockMvc,
                "app",
                "appclientsecret",
                UaaTestAccounts.DEFAULT_USERNAME,
                UaaTestAccounts.DEFAULT_PASSWORD,
                "",
                null,
                true
        );

        Snippet formParameters = formParameters(
                parameterWithName("token").description("The token").attributes(key("constraints").value("Required"), key("type").value(STRING))
        );

        Snippet responseFields = responseFields(
                fieldWithPath("active").type(BOOLEAN).description("Indicates whether or not the presented token is currently valid (given token has been issued by this authorization server, has not been revoked by the resource owner, and is within its given time window of validity)"),
                fieldWithPath("user_id").type(STRING).description("Only applicable for user tokens").optional(),
                fieldWithPath("user_name").type(STRING).description("Only applicable for user tokens").optional(),
                fieldWithPath("email").type(STRING).description("Only applicable for user tokens").optional(),
                fieldWithPath("client_id").description("A unique string representing the registration information provided by the client"),
                fieldWithPath("exp").description("[Expiration Time](https://tools.ietf.org/html/rfc7662#section-2.2) Claim"),
                fieldWithPath("authorities").type(ARRAY).description("Only applicable for client tokens").optional(),
                fieldWithPath("scope").description("List of scopes authorized by the user for this client"),
                fieldWithPath("jti").description("[JWT ID](https://tools.ietf.org/html/rfc7662#section-2.2) Claim"),
                fieldWithPath("aud").description("[Audience](https://tools.ietf.org/html/rfc7662#section-2.2) Claim"),
                fieldWithPath("sub").description("[Subject](https://tools.ietf.org/html/rfc7662#section-2.2) Claim"),
                fieldWithPath("iss").description("[Issuer](https://tools.ietf.org/html/rfc7662#section-2.2) Claim"),
                fieldWithPath("iat").description("[Issued At](https://tools.ietf.org/html/rfc7662#section-2.2) Claim"),
                fieldWithPath("cid").description("See `client_id`"),
                fieldWithPath("grant_type").description("The type of authentication being used to obtain the token, in this case `password`"),
                fieldWithPath("azp").description("Authorized party"),
                fieldWithPath("auth_time").type(NUMBER).description("Only applicable for user tokens").optional(),
                fieldWithPath("zid").description("Zone ID"),
                fieldWithPath("rev_sig").description("Revocation Signature - token revocation hash salted with at least client ID and client secret, and optionally various user values."),
                fieldWithPath("origin").type(STRING).description("Only applicable for user tokens").optional(),
                fieldWithPath("revocable").type(BOOLEAN).description("Set to true if this token is revocable").optional()
        );

        mockMvc.perform(post("/introspect")
                .header("Authorization", "bearer " + identityClientAccessToken)
                .param("token", identityAccessToken))
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestHeaders(
                        headerWithName("Authorization").description("One of the following authentication/authorization mechanisms:<br />" +
                                "<ul>" +
                                "<li>Bearer token for a registered client with authority `uaa.resource` &nbsp;&nbsp;<b>[Recommended]</b></li>" +
                                "<li>Basic authentication using client_id / client_secret for a registered client with authority `uaa.resource` &nbsp;&nbsp;<b>[Deprecated]</b></li>" +
                                "</ul>" +
                                "<b>If both bearer token and basic auth credentials are provided, only the bearer token will be used.</b>"
                        )
                ), formParameters, responseFields));
    }
}
