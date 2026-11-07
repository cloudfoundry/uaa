package org.cloudfoundry.identity.uaa.mock.codestore;

import org.cloudfoundry.identity.uaa.mock.EndpointDocs;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.restdocs.snippet.Snippet;

import static org.cloudfoundry.identity.uaa.test.SnippetUtils.fieldWithPath;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.headerWithName;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.NUMBER;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

class CodeStoreEndpointDocs extends EndpointDocs {

    private String loginToken;

    @BeforeEach
    void setUpToken() throws Exception {
        loginToken = MockMvcUtils.getClientOAuthAccessToken(mockMvc, "login", "loginsecret", "oauth.login");
    }

    @Test
    void document_create_code() throws Exception {
        Snippet requestHeaders = requestHeaders(
                headerWithName("Authorization").required().description("Bearer token with the scope `oauth.login` present, or a UAA admin token."),
                headerWithName(IdentityZoneSwitchingFilter.HEADER).optional(null).description("If using a `zones.<zoneId>.admin` scope/token, indicates what zone this request goes to by supplying a zone_id."),
                headerWithName(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER).optional(null).description("If using a `zones.<zoneId>.admin` scope/token, indicates what zone this request goes to by supplying a subdomain.")
        );

        Snippet requestFields = requestFields(
                fieldWithPath("data").required().type(STRING).description("The data stored with the code, returned when the code is redeemed. For the flows below this is a JSON document written as a string."),
                fieldWithPath("expiresAt").required().type(NUMBER).description("Expiry time of the code in milliseconds since the epoch. It must be in the future."),
                fieldWithPath("intent").required().type(STRING).description("What the code may be used for. It is required and must not be blank. The values `EMAIL` (email change verification), `INVITATION` (invitation acceptance) and `REGISTRATION` (account activation) are used by the UAA flows of the same name; the match is case sensitive. Any other value is stored as given, for codes that your own application creates and redeems.")
        );

        Snippet responseFields = responseFields(
                fieldWithPath("code").type(STRING).description("The generated one time code."),
                fieldWithPath("expiresAt").type(NUMBER).description("Expiry time of the code in milliseconds since the epoch."),
                fieldWithPath("data").type(STRING).description("The data stored with the code."),
                fieldWithPath("intent").type(STRING).description("The intent stored with the code.")
        );

        mockMvc.perform(post("/Codes")
                        .header("Authorization", "Bearer " + loginToken)
                        .contentType(APPLICATION_JSON)
                        .accept(APPLICATION_JSON)
                        .content("{\"data\":\"{\\\"user_id\\\":\\\"a-user-id\\\"}\",\"expiresAt\":" + (System.currentTimeMillis() + 600_000) + ",\"intent\":\"MY_APPLICATION_CODE\"}"))
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestHeaders, requestFields, responseFields));
    }
}
