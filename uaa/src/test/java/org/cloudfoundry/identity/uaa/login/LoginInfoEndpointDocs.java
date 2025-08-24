package org.cloudfoundry.identity.uaa.login;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.mock.EndpointDocs;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.util.Collections;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.fieldWithPath;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.headerWithName;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.parameterWithName;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.ARRAY;
import static org.springframework.restdocs.payload.JsonFieldType.BOOLEAN;
import static org.springframework.restdocs.payload.JsonFieldType.OBJECT;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.JsonFieldType.VARIES;
import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.formParameters;
import static org.springframework.restdocs.request.RequestDocumentation.queryParameters;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class LoginInfoEndpointDocs extends EndpointDocs {

    @Test
    void info_endpoint_for_json() throws Exception {
        Snippet queryParameters = queryParameters(
                parameterWithName("origin").optional(null).type(STRING).description("Use the configured prompts of the OpenID Connect Provider with the given origin key in the response. Fallback to zone values if no prompts are configured or origin is invalid.")
        );

        Snippet responseFields = responseFields(
                fieldWithPath("app.version").type(STRING).description("The UAA version"),
                fieldWithPath("commit_id").type(STRING).description("The GIT sha for the UAA version"),
                fieldWithPath("timestamp").type(STRING).description("JSON timestamp for the commit of the UAA version"),
                fieldWithPath("idpDefinitions").optional().type(OBJECT).description("A list of alias/url pairs of SAML IDP providers configured. Each url is the starting point to initiate the authentication process for the SAML identity provider."),
                fieldWithPath("idpDefinitions.*").optional().type(VARIES).description("The URL to initiate the authentication process for the SAML identity provider."),
                fieldWithPath("links").type(OBJECT).description("A list of alias/url pairs of configured action URLs for the UAA"),
                fieldWithPath("links.login").type(STRING).description("The link to the login host alias of the UAA"),
                fieldWithPath("links.uaa").type(STRING).description("The link to the uaa alias host of the UAA"),
                fieldWithPath("links.passwd").type(STRING).description("The link to the 'Forgot Password' functionality. Can be external or internal to the UAA"),
                fieldWithPath("links.register").type(STRING).description("The link to the 'Create Account' functionality. Can be external or internal to the UAA"),
                fieldWithPath("entityID").type(STRING).description("The UAA is always a SAML service provider. This field contains the configured entityID"),
                fieldWithPath("prompts").type(OBJECT).description("A list of name/value pairs of configured prompts that the UAA will login a user. Format for each prompt is [type, display name] where type can be 'text' or 'password'"),
                fieldWithPath("prompts.username").type(ARRAY).description("Information about the username prompt."),
                fieldWithPath("prompts.password").type(ARRAY).description("Information about the password prompt."),
                fieldWithPath("prompts.passcode").optional().type(ARRAY).description("If a SAML identity provider is configured, this prompt contains a URL to where the user can initiate the SAML authentication flow."),
                fieldWithPath("zone_name").type(STRING).description("The name of the zone invoked"),
                fieldWithPath("showLoginLinks").optional(false).type(BOOLEAN).description("Set to true if there are SAML or OAUTH/OIDC providers with a visible link on the login page.")
        );

        Snippet requestHeaders = requestHeaders(
                headerWithName(ACCEPT).description("When set to accept " + APPLICATION_JSON_VALUE + " the server will return prompts and server info in JSON format.")
        );

        mockMvc.perform(get("/info")
                .param("origin", "oidc-provider")
                .header(ACCEPT, APPLICATION_JSON_VALUE))
                .andExpect(status().isOk())
                .andDo(
                        document("{ClassName}/{methodName}",
                                preprocessResponse(prettyPrint()),
                                requestHeaders,
                                queryParameters,
                                responseFields)
                );
    }

    @Test
    void user_ui_login() throws Exception {
        Snippet formParameters = formParameters(
                parameterWithName("username").required().type(STRING).description("The username of the user, sometimes the email address."),
                parameterWithName("password").required().type(STRING).description("The user's password"),
                parameterWithName("X-Uaa-Csrf").required().type(STRING).description("Automatically configured by the server upon /login. Must match the value of the X-Uaa-Csrf cookie.")
        );
        Snippet requestHeaders = requestHeaders(
                headerWithName("Cookie").optional(null).type(STRING).description("*Required* Must contain the a value for the cookie X-Uaa-Csrf and that must match the request parameter of the same name")
        );

        mockMvc.perform(
                post("/login.do")
                        .with(cookieCsrf())
                        .header("Cookie", "X-Uaa-Csrf=12345a")
                        .param("username", "marissa")
                        .param("password", "koala")
                        .param("X-Uaa-Csrf", "12345a"))
                .andDo(
                        document("{ClassName}/{methodName}",
                                preprocessResponse(prettyPrint()),
                                requestHeaders,
                                formParameters))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"));
    }

    @Test
    void invalid_request() throws Exception {
        mockMvc.perform(get("/invalid_request"))
                .andDo(
                        document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()))
                )
                .andExpect(status().isOk());
    }

    @Test
    void passcode_request() throws Exception {
        ScimUserProvisioning userProvisioning = webApplicationContext.getBean(JdbcScimUserProvisioning.class);
        ScimUser marissa = userProvisioning.query("username eq \"marissa\" and origin eq \"uaa\"", IdentityZoneHolder.get().getId()).getFirst();
        UaaPrincipal uaaPrincipal = new UaaPrincipal(marissa.getId(), marissa.getUserName(), marissa.getPrimaryEmail(), marissa.getOrigin(), marissa.getExternalId(), IdentityZoneHolder.get().getId());
        UaaAuthentication principal = new UaaAuthentication(uaaPrincipal,
                Collections.singletonList(UaaAuthority.fromAuthorities("uaa.user")), null);

        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                new MockMvcUtils.MockSecurityContext(principal)
        );

        MockHttpServletRequestBuilder get = MockMvcRequestBuilders.get("/passcode")
                .accept(APPLICATION_JSON_VALUE)
                .session(session)
                .header("Cookie", "JSESSIONID=" + session.getId());

        mockMvc.perform(get)
                .andDo(
                        document("{ClassName}/{methodName}",
                                preprocessResponse(prettyPrint()),
                                requestHeaders(headerWithName("Cookie").required().description("JSESSIONID cookie to match the server side session of the authenticated user."))
                        )
                )

                .andExpect(status().isOk());
    }

    @Test
    void generate_auto_login_code() throws Exception {
        generate_auto_login_code(true);
    }

    Map<String, Object> generate_auto_login_code(boolean x) throws Exception {
        Snippet requestFields = requestFields(
                fieldWithPath("username").required().type(STRING).description("The username for the autologin request"),
                fieldWithPath("password").required().type(STRING).description("The password for the autologin request")
        );
        Snippet requestHeaders = requestHeaders(
                headerWithName("Authorization").required().description("Basic authorization header for the client making the autologin request"),
                headerWithName("Content-Type").required().description("Set to " + APPLICATION_JSON_VALUE),
                headerWithName("Accept").required().description("Set to " + APPLICATION_JSON_VALUE)
        );
        Snippet responseFields = responseFields(
                fieldWithPath("code").required().type(STRING).description("The code used to authenticate the user."),
                fieldWithPath("path").optional(null).type(STRING).description("Not used. Hardcoded to /oauth/authorize")
        );
        AutologinRequest request = new AutologinRequest();
        request.setUsername("marissa");
        request.setPassword("koala");
        String body = mockMvc.perform(
                post("/autologin")
                        .header("Authorization", "Basic " + new String(Base64.encode("admin:adminsecret".getBytes())))
                        .contentType(APPLICATION_JSON)
                        .accept(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(request)))
                .andDo(
                        document("{ClassName}/{methodName}",
                                preprocessResponse(prettyPrint()),
                                requestHeaders,
                                requestFields,
                                responseFields
                        )
                )
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return JsonUtils.readValue(body, new TypeReference<Map<String, Object>>() {
        });
    }

    @Test
    void perform_auto_login() throws Exception {
        Map<String, Object> code = generate_auto_login_code(true);
        Snippet queryParameters = queryParameters(
                parameterWithName("code").required().type(STRING).description("The code generated from the POST /autologin"),
                parameterWithName("client_id").required().type(STRING).description("The client_id that generated the autologin code")
        );
        mockMvc.perform(MockMvcRequestBuilders.get("/autologin")
                .param("code", (String) code.get("code"))
                .param("client_id", "admin"))
                .andDo(print())
                .andDo(
                        document("{ClassName}/{methodName}",
                                preprocessResponse(prettyPrint()),
                                queryParameters
                        )
                )
                .andExpect(redirectedUrl("home"));
    }

}
