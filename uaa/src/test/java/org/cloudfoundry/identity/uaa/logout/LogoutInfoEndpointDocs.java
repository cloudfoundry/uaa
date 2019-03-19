package org.cloudfoundry.identity.uaa.logout;

import org.cloudfoundry.identity.uaa.mock.EndpointDocs;
import org.junit.jupiter.api.Test;
import org.springframework.restdocs.headers.HeaderDocumentation;
import org.springframework.restdocs.snippet.Snippet;

import static org.cloudfoundry.identity.uaa.test.SnippetUtils.parameterWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.responseHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class LogoutInfoEndpointDocs extends EndpointDocs {

    @Test
    void logout() throws Exception {
        Snippet requestParameters = requestParameters(
                parameterWithName("redirect").optional("Identity Zone redirect uri").type(STRING).description("On a successful logout redirect the user to here, provided the URL is whitelisted"),
                parameterWithName("client_id").optional(null).type(STRING).description("On a successful logout the client's redirect_uri configuration is used as the redirect uri whitelist. If this value is not provided, the identity zone whitelist will be used instead.")
        );

        Snippet responseHeaders = responseHeaders(HeaderDocumentation.headerWithName("Location").description("Redirect URI"));

        mockMvc.perform(
                get("/logout.do")
                        .param("redirect", "http://redirect.localhost")
                        .param("client_id", "some_client_that_contains_redirect_uri_matching_request_param")
        ).andDo(
                document("{ClassName}/{methodName}",
                        preprocessResponse(prettyPrint()),
                        responseHeaders,
                        requestParameters))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://redirect.localhost"));
    }
}
