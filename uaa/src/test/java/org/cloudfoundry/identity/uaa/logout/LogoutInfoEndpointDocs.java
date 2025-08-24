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
import static org.springframework.restdocs.request.RequestDocumentation.queryParameters;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class LogoutInfoEndpointDocs extends EndpointDocs {

    @Test
    void logout() throws Exception {
        Snippet queryParameters = queryParameters(
                parameterWithName("redirect").optional("Identity Zone redirect uri").type(STRING).description("On a successful logout redirect the user to here, provided the URL is whitelisted"),
                parameterWithName("client_id").optional(null).type(STRING).description("On a successful logout the client's redirect_uri configuration is used as the redirect uri whitelist. If this value is not provided, the identity zone whitelist will be used instead."),
                parameterWithName("post_logout_redirect_uri").optional("Same as redirect uri, supports OIDC logout").type(STRING).description("Support the parameter for OIDC applications based on [OpenID Connect Session Management](https://openid.net/specs/openid-connect-session-1_0.html)."),
                parameterWithName("id_token_hint").optional("Support for OIDC logout").type(STRING).description("ID token from OIDC authentication. Used to identify the oauth client redirect uri whitelist. If this value is not provided, the identity zone whitelist will be used instead.redirect uri whitelist.")
        );

        Snippet responseHeaders = responseHeaders(HeaderDocumentation.headerWithName("Location").description("Redirect URI"));

        mockMvc.perform(
                get("/logout.do")
                        .param("redirect", "http://redirect.localhost")
                        .param("client_id", "some_client_that_contains_redirect_uri_matching_request_param")
                        .param("post_logout_redirect_uri", "http://redirect.localhost")
                        .param("id_token_hint", "eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vbG9jYWxob3N0OjgwODAvdWFhL3Rva2VuX2tleXMiLCJraWQiOiJsZWdhY3ktdG9rZW4ta2V5IiwidHlwIjoiSldUIn0.eyJzdWIiOiJhMGZlMGQ4OS1lZTJjLTRkMjEtYjFjMS0yNTQ2MzZjNzAxMTUiLCJhdWQiOlsic29tZV9jbGllbnRfdGhhdF9jb250YWluc19yZWRpcmVjdF91cmlfbWF0Y2hpbmdfcmVxdWVzdF9wYXJhbSJdLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvdWFhL29hdXRoL3Rva2VuIiwiYXpwIjoic29tZV9jbGllbnRfdGhhdF9jb250YWluc19yZWRpcmVjdF91cmlfbWF0Y2hpbmdfcmVxdWVzdF9wYXJhbSJ9.efdaWKPkFlgXyaHeQPGgIBAhiJgfcRScVbmuVWu-aUVCZsPnhjCcJQfxcXn61yKSbs8y5Pze3PkSCZdnyh_TvjHtqGBAvTRHuC3ZEDv7tZMQd3reyiS3pLCmn0OSwLB5-Ni4-_DDOcrVy-kOF4yU8rHXiXhGtcFZWpTShvXQgm_WNFKA-kHUOxzl4bQE5S2EnJUB7i1yUMYgaWnhYGzxcIm94AuYrD3OW2D2DFkEqJnQCYUIH6h3iNs_ABHs-O2JUtz12IRVLJCrmTssF-KRBfv_dIwLxSMgK3hI0i9yYZt_pbLbshNkeu32iZgvstSGZeoYbzpZq3mGp9M1CMtvvQ")
        ).andDo(
                document("{ClassName}/{methodName}",
                        preprocessResponse(prettyPrint()),
                        responseHeaders,
                        queryParameters))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://redirect.localhost"));
    }
}
