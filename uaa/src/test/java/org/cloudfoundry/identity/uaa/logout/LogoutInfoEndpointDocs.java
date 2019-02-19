package org.cloudfoundry.identity.uaa.logout;

import org.cloudfoundry.identity.uaa.SpringServletAndHoneycombTestConfig;
import org.cloudfoundry.identity.uaa.mock.EndpointDocs;
import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.test.HoneycombAuditEventTestListenerExtension;
import org.cloudfoundry.identity.uaa.test.HoneycombJdbcInterceptorExtension;
import org.cloudfoundry.identity.uaa.test.JUnitRestDocumentationExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.restdocs.headers.HeaderDocumentation;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;

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

@ExtendWith(SpringExtension.class)
@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(JUnitRestDocumentationExtension.class)
@ExtendWith(HoneycombJdbcInterceptorExtension.class)
@ExtendWith(HoneycombAuditEventTestListenerExtension.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = SpringServletAndHoneycombTestConfig.class)
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
