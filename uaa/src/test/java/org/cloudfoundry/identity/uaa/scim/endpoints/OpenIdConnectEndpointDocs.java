package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.mock.EndpointDocs;
import org.junit.jupiter.api.Test;
import org.springframework.restdocs.snippet.Snippet;

import static org.cloudfoundry.identity.uaa.test.SnippetUtils.fieldWithPath;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class OpenIdConnectEndpointDocs extends EndpointDocs {
    @Test
    void getWellKnownOpenidConf() throws Exception {
        Snippet responseFields = responseFields(
                fieldWithPath("issuer").description("URL using the https scheme with no query or fragment component that the OP asserts as its Issuer Identifier."),
                fieldWithPath("authorization_endpoint").description("URL of authorization endpoint."),
                fieldWithPath("token_endpoint").description("URL of token endpoint."),
                fieldWithPath("userinfo_endpoint").description("URL of the OP's UserInfo Endpoint."),
                fieldWithPath("jwks_uri").description("URL of the OP's JSON Web Key Set document."),
                fieldWithPath("end_session_endpoint").description("URL of the logout endpoint."),
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
                fieldWithPath("code_challenge_methods_supported").description("<small><mark>UAA 75.5.0</mark></small>JSON array containing a list of [PKCE](https://tools.ietf.org/html/rfc7636) code challenge methods supported by this authorization endpoint."),
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
