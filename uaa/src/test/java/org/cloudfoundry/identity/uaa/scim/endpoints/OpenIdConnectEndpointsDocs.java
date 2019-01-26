package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.TestSpringContext;
import org.cloudfoundry.identity.uaa.test.HoneycombAuditEventTestListenerExtension;
import org.cloudfoundry.identity.uaa.test.HoneycombJdbcInterceptorExtension;
import org.cloudfoundry.identity.uaa.test.JUnitRestDocumentationExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.restdocs.ManualRestDocumentation;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.cloudfoundry.identity.uaa.test.SnippetUtils.fieldWithPath;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.documentationConfiguration;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.templates.TemplateFormats.markdown;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@ExtendWith(JUnitRestDocumentationExtension.class)
@ExtendWith(HoneycombJdbcInterceptorExtension.class)
@ExtendWith(HoneycombAuditEventTestListenerExtension.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = TestSpringContext.class)
public class OpenIdConnectEndpointsDocs {

    @Autowired
    private WebApplicationContext webApplicationContext;
    private MockMvc mockMvc;

    @BeforeEach
    private void setUp(ManualRestDocumentation manualRestDocumentation) {
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .addFilter(springSecurityFilterChain)
            .apply(documentationConfiguration(manualRestDocumentation)
                    .uris().withPort(80).and()
                    .snippets()
                    .withTemplateFormat(markdown()))
            .build();
    }

    @Test
    public void getWellKnownOpenidConf() throws Exception {

        Snippet responseFields = responseFields(
            fieldWithPath("issuer").description("URL using the https scheme with no query or fragment component that the OP asserts as its Issuer Identifier."),
            fieldWithPath("authorization_endpoint").description("URL of authorization endpoint."),
            fieldWithPath("token_endpoint").description("URL of token endpoint."),
            fieldWithPath("userinfo_endpoint").description("URL of the OP's UserInfo Endpoint."),
            fieldWithPath("jwks_uri").description("URL of the OP's JSON Web Key Set document."),
            fieldWithPath("scopes_supported").description("JSON array containing a list of the OAuth 2.0 scope values that this server supports."),
            fieldWithPath("subject_types_supported").description("JSON array containing a list of the Subject Identifier types that this OP supports."),
            fieldWithPath("token_endpoint_auth_methods_supported").description("JSON array containing a list of Client Authentication methods supported by this Token Endpoint."),
            fieldWithPath("token_endpoint_auth_signing_alg_values_supported").description("JSON array containing a list of the JWS signing algorithms."),
            fieldWithPath("response_types_supported").description("JSON array containing a list of the OAuth 2.0 response_type values that this OP supports."),
            fieldWithPath("id_token_signing_alg_values_supported").description("JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT."),
            fieldWithPath("id_token_encryption_alg_values_supported").description("JSON array containing a list of the JWE encryption algorithms (alg values) supported by the OP."),
            fieldWithPath("claim_types_supported").description("JSON array containing a list of the Claim Types that the OpenID Provider supports."),
            fieldWithPath("claims_supported").description("JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for."),
            fieldWithPath("claims_parameter_supported").description("Boolean value specifying whether the OP supports use of the claims parameter."),
            fieldWithPath("service_documentation").description("URL of a page containing human-readable information that developers might want or need to know when using the OpenID Provider."),
            fieldWithPath("ui_locales_supported").description("Languages and scripts supported for the user interface.")
        );

        mockMvc.perform(
            get("/.well-known/openid-configuration")
            .servletPath("/.well-known/openid-configuration")
            .accept(APPLICATION_JSON))
            .andExpect(status().isOk())
            .andDo(document("{ClassName}/{methodName}",
                preprocessResponse(prettyPrint()),
                responseFields));
    }
}
