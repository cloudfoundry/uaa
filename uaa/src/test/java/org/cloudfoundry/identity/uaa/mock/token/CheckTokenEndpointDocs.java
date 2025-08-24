package org.cloudfoundry.identity.uaa.mock.token;

import org.apache.commons.codec.binary.Base64;
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

class CheckTokenEndpointDocs extends EndpointDocs {

    @Test
    void checkToken() throws Exception {
        String identityClientAuthorizationWithUaaResource = new String(Base64.encodeBase64("app:appclientsecret".getBytes()));

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
                parameterWithName("token").description("The token").attributes(key("constraints").value("Required"), key("type").value(STRING)),
                parameterWithName("scopes").description("String of comma-separated scopes, for checking presence of scopes on the token").attributes(key("constraints").value("Optional"), key("type").value(ARRAY))
        );

        Snippet responseFields = responseFields(
                fieldWithPath("user_id").type(STRING).description("Only applicable for user tokens").optional(),
                fieldWithPath("user_name").type(STRING).description("Only applicable for user tokens").optional(),
                fieldWithPath("email").type(STRING).description("Only applicable for user tokens").optional(),
                fieldWithPath("client_id").description("A unique string representing the registration information provided by the client"),
                fieldWithPath("exp").description("[Expiration Time](https://tools.ietf.org/html/rfc7519#section-4.1.4) Claim"),
                fieldWithPath("authorities").type(ARRAY).description("Only applicable for client tokens").optional(),
                fieldWithPath("scope").description("List of scopes authorized by the user for this client"),
                fieldWithPath("jti").description("[JWT ID](https://tools.ietf.org/html/rfc7519#section-4.1.7) Claim"),
                fieldWithPath("aud").description("[Audience](https://tools.ietf.org/html/rfc7519#section-4.1.3) Claim"),
                fieldWithPath("sub").description("[Subject](https://tools.ietf.org/html/rfc7519#section-4.1.2) Claim"),
                fieldWithPath("iss").description("[Issuer](https://tools.ietf.org/html/rfc7519#section-4.1.1) Claim"),
                fieldWithPath("iat").description("[Issued At](https://tools.ietf.org/html/rfc7519#section-4.1.6) Claim"),
                fieldWithPath("cid").description("See `client_id`"),
                fieldWithPath("grant_type").description("The type of authentication being used to obtain the token, in this case `password`"),
                fieldWithPath("azp").description("Authorized party"),
                fieldWithPath("auth_time").type(NUMBER).description("Only applicable for user tokens").optional(),
                fieldWithPath("zid").description("Zone ID"),
                fieldWithPath("rev_sig").description("Revocation Signature - token revocation hash salted with at least client ID and client secret, and optionally various user values."),
                fieldWithPath("origin").type(STRING).description("Only applicable for user tokens").optional(),
                fieldWithPath("revocable").type(BOOLEAN).description("Set to true if this token is revocable").optional()
        );

        mockMvc.perform(post("/check_token")
                .header("Authorization", "Basic " + identityClientAuthorizationWithUaaResource)
                .param("token", identityAccessToken)
                .param("scopes", "password.write,scim.userids"))
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestHeaders(
                        headerWithName("Authorization").description("Uses basic authorization with base64(resource_server:shared_secret) assuming the caller (a resource server) is actually also a registered client and has `uaa.resource` authority")
                ), formParameters, responseFields));
    }

}
