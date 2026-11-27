package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.mock.token.AbstractTokenMockMvcTests;
import org.cloudfoundry.identity.uaa.test.JUnitRestDocumentationExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.restdocs.ManualRestDocumentation;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.documentationConfiguration;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.templates.TemplateFormats.markdown;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@TestPropertySource(properties = {
        "uaa.admin-token-network-policy.enabled=true",
        "uaa.admin-token-network-policy.allowed-cidrs[0]=127.0.0.1/32"
})
@ExtendWith(JUnitRestDocumentationExtension.class)
class AdminTokenNetworkPolicyDocs extends AbstractTokenMockMvcTests {
    @Autowired
    private FilterChainProxy securityFilterChain;

    @BeforeEach
    void configureDocumentation(ManualRestDocumentation documentation) {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(securityFilterChain)
                .apply(documentationConfiguration(documentation).snippets().withTemplateFormat(markdown()))
                .build();
    }

    @Test
    void deniedAdministrativeIssuance() throws Exception {
        mockMvc.perform(post("/oauth/token").with(httpBasic("admin", "adminsecret"))
                        .contentType(APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials").param("scope", "uaa.admin")
                        .with(request -> { request.setRemoteAddr("198.51.100.1"); return request; }))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("access_denied"))
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()),
                        responseFields(
                                fieldWithPath("error").description("OAuth error: access_denied"),
                                fieldWithPath("error_description").description("Administrative token source address is not allowed"))));
    }

    @Test
    void deniedAdministrativeUse() throws Exception {
        mockMvc.perform(get("/Users").header("Authorization", "Bearer " + adminToken)
                        .header("X-Forwarded-For", "127.0.0.1")
                        .with(request -> { request.setRemoteAddr("198.51.100.1"); return request; }))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("access_denied"));
    }
}
