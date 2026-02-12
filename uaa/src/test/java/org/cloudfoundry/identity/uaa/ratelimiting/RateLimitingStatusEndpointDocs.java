package org.cloudfoundry.identity.uaa.ratelimiting;

import org.cloudfoundry.identity.uaa.mock.EndpointDocs;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.restdocs.snippet.Snippet;

import static org.cloudfoundry.identity.uaa.test.SnippetUtils.fieldWithPath;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.NUMBER;
import static org.springframework.restdocs.payload.JsonFieldType.OBJECT;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class RateLimitingStatusEndpointDocs extends EndpointDocs {

    private String adminToken;

    @BeforeEach
    void setUp() throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "uaa.admin");
    }

    @Test
    void getRateLimitingStatus() throws Exception {
        Snippet requestHeaders = requestHeaders(
                headerWithName("Authorization").description("Bearer token with `uaa.admin` scope"),
                headerWithName("Accept").optional().description("application/json"),
                headerWithName("Host").description("Must be the default authentication zone")
        );

        Snippet responseFields = responseFields(
                fieldWithPath("current").type(OBJECT).description("Current rate limiting status information"),
                fieldWithPath("current.status").type(STRING).description("Overall status of UAA rate limiting. One of: `DISABLED` (no configuration given, rate limiting is off), `ACTIVE` (configuration successfully parsed and active), or `PENDING` (configuration file could not be read successfully)"),
                fieldWithPath("current.asOf").type(STRING).description("UTC ISO8601 timestamp to the second indicating when this status was generated"),
                fieldWithPath("current.error").optional().type(STRING).description("Error message if the configuration could not be read successfully. Only present when status is `PENDING`"),
                fieldWithPath("current.credentialIdExtractor").optional().type(STRING).description("Credential ID configuration that is currently used. Only present when status is `ACTIVE`"),
                fieldWithPath("current.loggingLevel").optional().type(STRING).description("Logging option that is currently used. Only present when status is `ACTIVE`"),
                fieldWithPath("current.limiterMappings").optional().type(NUMBER).description("Number of limiters from the configuration (the size of limiterMappings from the config file). Only present when status is `ACTIVE` and limiters are configured"),
                fieldWithPath("fromSource").optional().type(STRING).description("Location of the config file that is currently applied. Can be a local file path or http/https URL. Only present when status is `ACTIVE` or `PENDING`")
        );

        mockMvc.perform(
                get("/RateLimitingStatus")
                        .servletPath("/RateLimitingStatus")
                        .header("Authorization", "Bearer " + adminToken)
                        .header("Host", "localhost")
                        .accept(APPLICATION_JSON))
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}",
                        preprocessResponse(prettyPrint()),
                        requestHeaders,
                        responseFields));
    }
}
